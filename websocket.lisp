;;; -*- Mode: lisp; Syntax: ansi-common-lisp; Base: 10; Package: org.datagraph.spocq.server.implementation; -*-
;;; (load #p"patches/model.lisp")

(in-package :org.datagraph.spocq.server.implementation)
;;; (trace ws::process-websocket-frame http:respond-to-request tbnl::get-request-data hunchensocket::handle-handshake)
;;; (trace tbnl::START-LISTENING tbnl::EXECUTE-ACCEPTOR tbnl::HANDLE-INCOMING-CONNECTION tbnl::process-connection)

;;; (trace tbnl::process-connection http::respond-to-connection ws::websocket-request-loop ws::process-websocket-message spocq.si::propagation-server)

#|
Augment the execution control structure of the HTTP server to support WebSocket connections.
This involves
- extend the acceptor logic in process-connection to recognize an upgrade and
  allow that thread retain the connection to run a websocket request loop
  where ws::process-websocket-message serves as the equivalent to
  tbnl::process-connection, but using vector streams to present the input and
  capture the output.
- otherwise, retain the standard response function dispatch mechanism to handle
  http requests in request/response mode as before
- route replicated content to websocket output streams according to request
  "Content-Disposition" header values.
  - provide a control operator to register websocket response streams with the
    acceptor according to disposition
  - provide a replication side-effect for selected graph store operations, to
    use the request disposition to select websocket output streams and distribute
    requests to them
- implement an in-memory patch operator which interprets the sections of a
  multipart mime document as DELETE/POST/PUT operations.
  (this could support section-specific dispositions and/or content-based logic
  for dynamic routing based on a computed disposition.)

The extension is based on hunchensocket, which implements the framing and
message un/marshalling, but it retains the http dispatch and message syntax of
the core server.
(https://github.com/joaotavora/hunchensocket)
it adds just the propagation-server resource function which adds two resources
- /ws is the target for the initial websocket upgrade request and responds with
  no content
- /:account/:repository/disposition is an authenticated resource which sets the
  disposition for the respective response stream

in order to provide the net-facing proxy, nginx is configured as for a spocq
server, but with a long timeout

location ^~ /ws {
  # when run on a specific server
  proxy_pass       http://spocq_ws;
  # otherwise just as normal
  # proxy_pass http://spocq;
  proxy_set_header Host      $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header DYDRA_SERVICE websocket;
  fastcgi_read_timeout 1d;
  proxy_read_timeout 1d;

  proxy_http_version 1.0; # no chunking
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  # when run on a specific servier with a prefix
  # leave /ws alone, but elimiate a prefix elsewhere
  rewrite ^/ws(/.*)$ $1 break;
}
|#

(defparameter ws:*class.request* 'ws:request)
(defparameter ws:*class.response* 'ws:response)
(defparameter ws:*request* nil)
(defparameter ws:*response* nil)

(defparameter *ws-request-limit* 16)
(defparameter *ws-thread-limit* 8)
(defparameter ws:*acceptor* nil)

(defclass ws:acceptor (hunchensocket::websocket-acceptor spocq-acceptor) ; (tbnl:acceptor)
  ((version :initform :rfc-6455
            :reader acceptor-version)
   (protocol
    :initform "HTTP 1.0"
    :reader ws:acceptor-protocol
    :documentation "The effective http protocol disables chunking as the message is a single unit.")
   (request-limit
    :initform *ws-request-limit*
    :initarg :request-limit
    :reader acceptor-request-limit)
   (thread-limit
    :initform *ws-thread-limit*
    :initarg :thread-limit
    :reader acceptor-thread-limit)
   (threads-in-progress
    :initform 0
    :accessor acceptor-threads-in-progress)
   (wait-queue
    :initform (tbnl::make-condition-variable)
    :reader acceptor-wait-queue
    :documentation
    "A queue that we use to wait for a free connection.")
   (wait-lock
    :initform (bt:make-lock "acceptor-wait-lock")
    :reader acceptor-wait-lock
    :documentation
    "The lock for the connection wait queue.")
   (message-queue
    :initform (spocq.i::make-pool :name "ws message pool")
    :reader acceptor-message-queue
    :documentation
    "Passes message to the thread which emits and confirms receipts and responses.
     These will be the publish and confirmation messages read and passed through from the main acceptor thread
     and the response messages from the respective request processing thread.")
   (message-thread
    :accessor ws::acceptor-message-thread
    :documentation
    "A dependent thread to multiplex response messages over the acceptor connection, manage their timeouts,
     and correlate confirmation messages.")
   (propagation-lock
    :initform (bt:make-lock "acceptor-propagation-lock")
    :reader ws::acceptor-propagation-lock
    :documentation
    "The lock for the managing propagation.")
   (propagation-streams
    :initform (make-hash-table :test 'equal)
    :reader ws::acceptor-propagation-streams
    :documentation
    "A registry of streams to serve as propagation targets, indexed by disposition."))
  (:documentation
   "Combine ws-specific attributes with standard http acceptor behaviour and connection limits from
    task-manager"))

(defmethod initialize-instance :after ((instance ws:acceptor) &key)
  (setf (tbnl::acceptor-output-chunking-p instance) nil))

(defclass ws:request (spocq-request)
  ((hunchensocket::state
    :initform nil
    :reader acceptor-state
    :documentation "websocket frame state")
   (hunchensocket::pending-fragments
    :initform nil
    :reader ws::request-pending-fragments)
   (hunchensocket::pending-opcode :initform nil)
   (content
    :initarg :content :initform #()
    :reader ws::request-content
    :documentation
    "caches the websocket frame content")))

(defun ws:make-request (&rest initargs)
  (apply #'make-instance ws:*class.request* :acceptor initargs))

(defclass ws:response (spocq-response)
  ())

(defun ws:make-response (&rest initargs)
  (apply #'make-instance ws:*class.response* :acceptor initargs))

(defclass ws:output-stream (http:output-stream)
  ((write-lock
    :initform (bt:make-lock "stream-write-lock")
    :reader stream-write-lock
    :documentation
    "The lock to serialize socket output.")
   (disposition
    :initform nil
    :accessor ws::stream-disposition
    :documentation "registers patterns for terms for which the stream's client
     is to be informed")
   (node-address
    :initform nil
    :accessor ws::stream-node-address
    :documentation "Set from an ETag header provided with a request which sets
     the disposition to enable possible round-trip suppression."))
  (:documentation
   "Extend an http output stream with a lock to serialize output and a registry for client's terms
    as well as a dispositoon for routing and a location to suppress round-trip propagation."))

(defmethod initialize-instance :after ((stream ws:output-stream) &key)
  (setf (chunga:chunked-stream-output-chunking-p stream) nil)
  )
  

(defclass ws:query (dydra:query)
  ()
  (:metaclass org.datagraph.spocq.implementation::applicable-query-class)
  (:documentation "Distinguish ws queries in order to specialize spocq.i::initiate-task to iterate
 over revisions"))


;;; websocket splices on to
;;; - tbnl:process-connection
;;; - tbnl:respond-to-request
;;; see https://github.com/joaotavora/hunchensocket/blob/master/hunchensocket.lisp

(defstruct (ws::frame (:constructor ws::make-frame))
  fin
  (resv1 0)
  (resv2 0)
  (resv3 0)
  (opcode 0)
  (mask 0)
  (length 0)
  (masking-key nil)
  (data #()))

(defun ws::decode-frame (frame)
  (let* ((byte0 (aref frame 0))
         (byte1 (aref frame 1))
         (masked-bit (ldb (byte 1 7) byte1)))
  (ws::make-frame :fin (ldb (byte 1 7) byte0)
                  :opcode (ldb (byte 4 0) byte0)
                  :mask (eql masked-bit 1)
                  :length (case (ldb (byte 7 0) byte1)
                            (126 (+ (ash (aref frame 2) 8) (aref frame 3)))
                            (127 (reduce #'(lambda (l r) (+ (ash l 8) r)) frame :start 2 :end 10 :initial-value 0))
                            (t (ldb (byte 7 0) byte1)))
                  :masking-key (when (eql masked-bit 1) (subseq frame 10 13))
                  :data (subseq frame (if (eql masked-bit 1) 13 10)))))
                  

(defgeneric ws:write-frame (stream opcode content)
  (:documentation
   "Send the frame to the websocket client.
 Serialize output with the stream's lock.")
  (:method ((stream ws:output-stream) opcode (content string))
    ;; if a strin gis passed, it is an error message
    (ws:write-frame stream opcode (map 'vector #'char-code content)))
  (:method ((stream ws:output-stream) opcode content)
    (bt:with-lock-held ((stream-write-lock stream))
      (hunchensocket::write-frame (CHUNGA:CHUNKED-STREAM-STREAM stream) opcode content)
      ;; (hunchensocket::write-frame stream opcode content)
      ))
  (:method ((stream stream) (opcode number) content)
    (hunchensocket::write-frame stream opcode content))
  (:method ((stream ws:output-stream) (media-type mime:mime-type) content)
    (ws:write-frame stream (ws:mime-type-opcode media-type) content)))
;;; tcpdump -A -s 0 -i lo tcp and port 8104

#+(or)
(let ((data (make-array 256))
      (stream (make-instance 'de.setf.utility.implementation::vector-output-stream)))
  (dotimes (x (length data)) (setf (aref data x) x))
  (ws:write-frame stream hunchensocket::+binary-frame+ data)
  (let ((vector (DE.SETF.UTILITY.IMPLEMENTATION::vector-stream-vector stream)))
    (values (ws::decode-frame vector)
            vector)))

(defgeneric ws::close-connection (stream &key status reason)
  (:method ((stream ws:output-stream) &key (status 1011) reason)
    (ws:write-frame stream status reason)))

(defgeneric ws:mime-type-opcode (media-type)
  (:method ((media-type null))
    hunchensocket::+binary-frame+)
  (:method ((media-type mime:mime-type))
    (if (binary-mime-type-p media-type)
        hunchensocket::+binary-frame+
        hunchensocket::+text-frame+)))


(defgeneric ws::websocket-request-loop (acceptor request response &key version)

  (:method ((acceptor ws:acceptor) request response
            &key (version (acceptor-version acceptor)))
  "Implements the main WebSocket loop for supported protocol
versions. Framing is handled automatically, CLIENT handles the actual
payloads."
  (ecase version
    (:rfc-6455
     (handler-bind ((hunchensocket::websocket-error
                      #'(lambda (error)
                          (http:log-error "websocket-request-loop: websocket error in http response: [~a] ~a" (type-of error) error)
                          (ws::close-connection
                           (http:response-content-stream response)
                           :status (hunchensocket::websocket-error-status error)
                           :reason (format nil "Websocket error: [~a] ~a" (type-of error) error))))
                    (flexi-streams:external-format-error
                      #'(lambda (error)
                          (http:log-error "websocket-request-loop: flexistream error in http response: [~a] ~a" (type-of error) error)
                          (ws::close-connection
                             (http:response-content-stream response)
                             :status 1007
                             :reason "Bad UTF-8")))
                    (http:error
                     (lambda (c)
                       (http:log-error "websocket-request-loop: http error in http response: [~a] ~a" (type-of c) c)
                       (ws::close-connection
                        (http:response-content-stream response)
                        :status 1011
                        :reason (format nil "HTTP error: [~a] ~a" (type-of c) c))))
                    (error
                      #'(lambda (c)
                          (http:log-error "websocket-request-loop: error in http response: [~a] ~a" (type-of c) c)
                          (ws::close-connection
                             (http:response-content-stream response)
                             :status 1011
                             :reason (format nil "Error: [~a] ~a" (type-of c) c)))))
       (loop do (ws::process-websocket-frame acceptor request response)
         while (not (eq :closed (acceptor-state request)))))))))


(defgeneric ws::process-websocket-message (acceptor request response body)
  (:documentation "For each websocket body, establish the processing context,
 in terms of *hunchentoot-stream* w/o chunking, wrap the content
 in an http stream, create a vector stream to capture output, parse the headers
 establish the request/response context
   tbnl::*request* : the reified request instance
   tbnl::*reply* : the reified response instance
 then proceed as with http processing via respond-to-request on the initial
 acceptor and the request and response instances.
 When the request completes, extract and send the response body.")

  (:method ((acceptor ws:acceptor) request acceptor-response body)
    (handler-bind 
        ((error (lambda (c)
                  (print (list :process-websocket-message c))
                  ;; do not handle it, just log
                  (format *error-output* "ws::process-websocket-message: error: [~a] ~a" (type-of c) c)
                  (format *error-output* "~%~a" (tbnl::get-backtrace)))))
    (http:log-debug "process-websocket-message: frame [~a]"
                    (map 'string #'code-char body))
    (let* ((frame-stream (make-instance 'de.setf.utility.implementation::vector-input-stream
                           :vector body))
           (tbnl::*hunchentoot-stream* frame-stream))
      (multiple-value-bind (headers-in method url-string protocol)
                           (tbnl::get-request-data tbnl::*hunchentoot-stream*)
        ;; check if there was a request at all
        (unless method
          (ws:write-frame (http:response-content-stream acceptor-response)
                          hunchensocket::+text-frame+
                          body)
          (return-from ws::process-websocket-message nil))
        (setf protocol :http/1.0)
        ;; bind per-request special variables, then process the
        ;; request - note that *ACCEPTOR* was bound by an aound method
        (let* ((tbnl:*acceptor* acceptor)
               (output-stream (make-instance 'de.setf.utility.implementation::vector-output-stream))
               (tbnl:*reply* (ws:make-response acceptor
                                                :server-protocol protocol
                                                ;; create the output stream which supports character output for the headers
                                                ;; with the initial character encoding set to ascii
                                                :content-stream (make-instance 'http:output-stream :real-stream output-stream)))
               (input-stream (make-instance 'http:input-stream :real-stream frame-stream))
               (tbnl:*request* (ws:make-request acceptor
                                                 ;; bogus, but ?
                                                 :socket nil ; (tbnl::request-socket request)
                                                 :headers-in headers-in
                                                 :content-stream input-stream
                                                 :content body
                                                 :method method
                                                 :uri url-string
                                                 :server-protocol protocol))
               (http:*request* tbnl::*request*)
               (http:*response* tbnl::*reply*)
               (tbnl::*tmp-files* nil)
               (tbnl::*session* nil)
               (dydra:*class.query* 'ws:query))
          (setf (http:response-request tbnl::*reply*) tbnl::*request*)
          (setf (http:request-response tbnl::*request*) tbnl::*reply*)
          (http:respond-to-request acceptor http:*request* http:*response*)
          (let ((content (de.setf.utility.implementation::vector-stream-vector
                          (chunga:chunked-stream-stream (http:response-content-stream http:*response*)))))
            ;; this needs to hold the acceptor's lock
            (ws:write-frame (http:response-content-stream acceptor-response)
                            (http:response-media-type http:*response*)
                            content)
            (tbnl::acceptor-log-access acceptor :return-code (http:response-status-code http:*response*)
                                       :format-control "~:[-~@[ (~A)~]~;~:*~A~@[ (~A)~]~] ~A [~A--~A] ~A \"~A ~A~@[?~A~] ~
                                                        ~A\" ~D ~:[-~;~:*~D~] \"~:[-~;~:*~A~]\"/ws \"~:[-~;~:*~A~]\"~%"))))))))


(in-package :hunchensocket)

(defgeneric ws::check-websocket-frame (acceptor request frame)
  (:method ((acceptor ws:acceptor) (request ws:request) frame)
    (let* ((length (frame-payload-length frame))
           (total (+ length
                     (reduce #'+ (mapcar
                                  #'frame-payload-length
                                  (ws::request-pending-fragments request))))))
      (cond ((> length #xffff) ; 65KiB
             (websocket-error 1009 "Message fragment too big"))
            ((> total #xfffff) ; 1 MiB
             (websocket-error 1009 "Total message too big"))))))

(defun ws::process-websocket-frame (acceptor request response)
  (handler-bind 
      (#+(or)(hunchensocket::websocket-error (lambda (c)
                                         (print (list :seen-as-websocket-rror c))
                                         (signal c)))
       (error (lambda (c)
                (print (list :seen-as-rror c))
                ;; do not handle it, just log
                (format *error-output* "http::process-websocket-frame: error in frame processing: [~a] ~a" (type-of c) c)
                (format *error-output* "~%~a" (tbnl::get-backtrace)))))
    (with-slots (state pending-fragments pending-opcode) request
      (let ((frame nil))
        (loop for count below 3
          until frame
          do (handler-case (setf frame (hunchensocket::read-frame (http:request-content-stream request)))
               (sb-sys:io-timeout (c)
                 (declare (ignore c))
                 (ws:write-frame (http:response-content-stream response) +ping+
                                 (map 'vector #'char-code (format nil "ping ~d" count)))))
          finally (unless frame
                    (http:log-debug "ws:process-websocket-frame: io-timeout: ~a" request)))
                                  
        (cond (frame
            (with-slots (opcode finp payload-length masking-key) frame
              (flet ((maybe-accept-data-frame ()
                       (ws::check-websocket-frame acceptor request frame)
                       (read-application-data (http:request-content-stream request) frame)))
                (cond
                 ((eq :awaiting-close state)
                  ;; We're waiting a close because we explicitly sent one to the
                  ;; client. Error out if the next message is not a close.
                  ;;
                  (unless (eq opcode +connection-close+)
                    (websocket-error
                     1002 "Expected connection close from client, got 0x~x" opcode))
                  (setq state :closed))
                 ((not finp)
                  ;; This is a non-FIN fragment Check opcode, append to client's
                  ;; fragments.
                  ;;
                  (cond ((and (= opcode +continuation-frame+)
                              (not pending-fragments))
                         (websocket-error
                          1002 "Unexpected continuation frame"))
                        ((control-frame-p opcode)
                         (websocket-error
                          1002 "Control frames can't be fragmented"))
                        ((and pending-fragments
                              (/= opcode +continuation-frame+))
                         (websocket-error
                          1002 "Not discarding initiated fragment sequence"))
                        (t
                         ;; A data frame, is either initiaing a new fragment sequence
                         ;; or continuing one
                         ;;
                         (maybe-accept-data-frame)
                         (cond ((= opcode +continuation-frame+)
                                (push frame pending-fragments))
                               (t
                                (setq pending-opcode opcode
                                      pending-fragments (list frame)))))))
                 ((and pending-fragments
                       (not (or (control-frame-p opcode)
                                (= opcode +continuation-frame+))))
                  ;; This is a FIN fragment and (1) there are pending fragments and (2)
                  ;; this isn't a control or continuation frame. Error out.
                  ;;
                  (websocket-error
                   1002 "Only control frames can interleave fragment sequences."))
                 (t
                  ;; This is a final, FIN fragment. So first read the fragment's data
                  ;; into the `data' slot.
                  ;;
                  (cond
                   ((not (control-frame-p opcode))
                    ;; This is either a single-fragment data frame or a continuation
                    ;; frame. Join the fragments and keep on processing. Join any
                    ;; outstanding fragments and process the message.
                    ;;
                    (maybe-accept-data-frame)
                    (unless pending-opcode
                      (setq pending-opcode opcode))
                    (let* ((ordered-frames
                            (reverse (cons frame pending-fragments)))
                           (body (apply #'concatenate 'vector
                                        (mapcar #'frame-data
                                                ordered-frames))))
                      (setf pending-fragments nil)
                      (handler-case
                          (ws::process-websocket-message acceptor request response body)
                        (error (e)
                          (websocket-error
                           1002 (format nil "Websocket message error: ~a" e))))))
                   ((eq +ping+ opcode)
                    ;; Reply to client-initiated ping with a server-pong with the
                    ;; same data
                    (ws:write-frame (http:response-content-stream response) +pong+ (frame-data frame)))
                   ((eq +connection-close+ opcode)
                    ;; Reply to client-initiated close with a server-close with the
                    ;; same data
                    ;;
                    (ws:write-frame (http:response-content-stream response) +connection-close+ (frame-data frame))
                    (setq state :closed))
                   ((eq +pong+ opcode)
                    ;; Probably just a heartbeat, don't do anything.
                    )
                   (t
                    (websocket-error
                     1002 "Client sent unknown opcode ~a" opcode))))))))
              (t
               (http:log-info "ws:process-websocket-frame: timeout: ~a" request)
               (setq state :closed)))))))


;;; toplevel with websocket support

(in-package :org.datagraph.spocq.server.implementation)

(defun ws:main (&rest args &key (init-name (or (getarg "--spocqinit") "init-websockets")) &allow-other-keys)
  "Provide the main entry point for a service with websocket support:
 - configure from --spocqinit
 - initialize spocq runtime to start logs and establish connection to store
 - run the ws service
 "
  (when (getarg "--spocqhelp") ;; --help is seen by sbcl
    (format *trace-output* "~a :~{~% ~a~}~%" (first (spocq.i::command-line-argument-list))
            (sort spocq.i::*getarg-options* #'string-lessp))
    (exit-lisp 0))
  (setq spocq.i:*configuration-pathname*
        (merge-pathnames init-name (make-pathname :directory '(:relative) :type "sxp")))
  (handler-case (spocq.i:initialize-spocq)
    (error (condition)
      (log-error "ws:main: termination due to condition: ~a" condition)
      (spocq.i::maybe-exit-on-error)))
  ;; avoid first initialization error
  (handler-case (make-instance 'spocq.i::query :sse-expression () :id "" :repository-id "system/system")
    (error (c) (warn "initial instantiation error: ~a" c))
    (:no-error (result) (format t "instantiated: ~a" result)))
  (apply #'ws:run args))

(defun ws:run (&key (request-limit *mqtt-request-limit*)
                      (thread-limit *mqtt-thread-limit*)
                      (request-class nil request-class-supplied-p)
                      (response-class nil response-class-supplied-p)
                      (query-class nil query-class-supplied-p)
                      (host-name (dydra:server-host-name))
                      (host-package (or (find-package host-name)
                                        (make-package host-name :use ())))
                      (port *host-port*))
                      
  "Initiate the ws service with a background admin process.
 - create an acceptor
 - bind the response operators
 - start the acceptor
 "
  (spocq.i:enable-interrupt :sigterm #'spocq.i:sigterm-handler)
  (unless spocq.i:*start-timestamp*
    (setq spocq.i:*start-timestamp* (iso-time)))
  (setq spocq.i:*response-header-types* nil)  ; to be sure that no prefixes are sent out
  #+sbcl(sb-ext:gc :full t)

  (dydra:log-info "Start Websockets ~a." (iso-time))

  (when request-class-supplied-p
    (setq ws:*class.request* request-class))
  (when response-class-supplied-p
    (setq ws:*class.response* response-class))
  (when query-class-supplied-p
    (setq dydra:*class.query* query-class))

  (setq ws:*acceptor*
        (make-instance 'ws:acceptor
          :port port
          :address host-name
          :name (format nil "~a@~a" "dydra.spocq" (spocq.i::host-name))
          :request-class request-class
          :response-class response-class
          :thread-limit thread-limit
          :request-limit request-limit
          ))
  (setq *spocq-acceptor* ws:*acceptor*)
  (import (cons 'spocq.si::propagation-server
                *response-functions*)
          host-package)
  (with-package-iterator (next host-package :internal)
    (loop (multiple-value-bind (symbol-p symbol) (next)
            (unless symbol-p (return))
            (export symbol host-package))))
  
  (setf (http:acceptor-dispatch-function ws:*acceptor*) host-package)
  
  (handler-case (http:start ws:*acceptor*)
    (error (c)
      (dydra:log-warn "Unable to initiate service: ~a" c)
      (spocq.i::maybe-exit-on-error)
      (break "Unable to initiate service: ~a" c)))
  (dydra:log-info "Accepting websockets on ~a." port)
  (spocq.i:run-processing-threads)
  )



(in-package :tbnl)

;;; http integration via hunchentoot initiation crontrol-flow

(defmethod start ((acceptor ws:acceptor))
  #+(or) ;; no extra thread
  (setf (ws::acceptor-message-thread acceptor)
        (bt:make-thread #'(lambda () (ws::send-messages acceptor))
                        :name "ws send-message thread"))
  (call-next-method))

(defmethod stop ((acceptor ws:acceptor) &key soft)
  (declare (ignore soft))
  (call-next-method)
  #+(or)
  (bt:destroy-thread (ws::acceptor-message-thread acceptor)))

(defmethod start-listening ((acceptor ws:acceptor))
  ;; unchanged from base class
  (call-next-method))

(defmethod process-connection ((acceptor ws:acceptor) (socket t))
  "Given acceptor, a ws:acceptor, and socket, a connection socket,
 for each request, perform the websockt handshake and protocol switch.
 then delegate to sebsocke logic for subsequent message handling."

  (let ((socket-stream (make-socket-stream socket acceptor)))
    (unwind-protect
      ;; process requests until either the acceptor is shut down,
      ;; *CLOSE-HUNCHENTOOT-STREAM* has been set to T by the
      ;; handler, or the peer fails to send a request
      ;; use as the base stream either the original socket stream or, if the connector
      ;; supports ssl, a wrapped stream for ssl support
      (let* ((acceptor-stream (initialize-connection-stream acceptor socket-stream))
             (tbnl::*hunchentoot-stream* acceptor-stream)) ; provide the dynamic binding
          ;; establish http condition handlers and an error handler which mapps to internal-error
          (handler-bind
            (;; declared conditions are handled according to their report implementation
             (http:error (lambda (c)
                               (when tbnl::*reply*  ;; can happen while request is being parsed
                                 (http:send-condition tbnl::*reply* c)
                                 ;; log the condition as request completion
                                 (acceptor-log-access acceptor :return-code (http:response-status-code tbnl::*reply*)))
                               (http:log-error "process-connection: http error in http response: [~a] ~a" (type-of c) c)
                               ;;(describe tbnl::*reply*)
                               ;;(describe (http:response-content-stream tbnl::*reply*))
                               ;;(dotimes (x 100) (write-char #\. (http:response-content-stream tbnl::*reply*)))
                               ;;(finish-output (http:response-content-stream tbnl::*reply*))
                               ;;(dotimes (x 100) (write-byte (char-code #\,) acceptor-stream))
                               ;;(finish-output acceptor-stream)
                               ;; (format *trace-output*  "sent~%~a~%" c)
                               (return-from tbnl:process-connection
                                 (values nil c nil)))))
            (handler-bind
              ;; establish an additional level to permit a general handler which maps to http:condition
              (;; at this level decline to handle http:condition, to cause it to pass one level up
               (http:condition (lambda (c)
                                 (signal c)))
               ;; a connection error is suppressed by returning from the connection handler.
               ;; this does not try to continue as any stream's socket
               (usocket:connection-aborted-error (lambda (c) 
                                                   (http:log-error "process-connection: [~a] ~a" (type-of c) c)
                                                   (return-from tbnl:process-connection nil)))
               #+sbcl  ;; caused by a broken pipe
               (sb-int:simple-stream-error (lambda (c)
                                             (http:log-error "process-connection: [~a] ~a" (type-of c) c)
                                             (return-from tbnl:process-connection nil)))
               ;; while any other error is handled as per acceptor, where the default implementation
               ;; will be to log and re-signal as an http:internal-error, but other mapping are possible
               ;; as well as declining to handle in which the condition is re-signaled as an internal error
               (error (lambda (c)
                        (http:handle-condition acceptor c)
                        ;; if it remains unhandled, then resignal as an internal error
                        (http:log-error "process-connection: unhandled error in http response: [~a] ~a" (type-of c) c)
                        (http:log-error "~a" (get-backtrace))
                        ;; re-signal to the acceptor's general handler
                        (http:internal-error "process-connection: unhandled error in http response: [~a] ~a" (type-of c) c))))
            
              (loop
                (let ((tbnl::*close-hunchentoot-stream* t))
                  (when (acceptor-shutdown-p acceptor)
                    (return))
                  (multiple-value-bind (headers-in method url-string protocol)
                                       (get-request-data tbnl::*hunchentoot-stream*)
                    ;; check if there was a request at all
                    (unless method
                      (return))
                    ;; bind per-request special variables, then process the
                    ;; request - note that *ACCEPTOR* was bound by an aound method
                    (let* ((output-stream (make-instance 'ws:output-stream :real-stream tbnl::*hunchentoot-stream*))
                           (tbnl::*reply* (ws:make-response acceptor
                                                        :server-protocol protocol
                                                        ;; create the output stream which supports character output for the headers
                                                        ;; with the initial character encoding set to ascii
                                                        :content-stream output-stream))
                           (input-stream (make-instance 'http:input-stream :real-stream tbnl::*hunchentoot-stream*))
                           (tbnl::*request* (ws:make-request acceptor
                                                         :socket socket
                                                         :headers-in headers-in
                                                         :content-stream input-stream
                                                         :method method
                                                         :uri url-string
                                                         :server-protocol protocol))
                           (tbnl::*tmp-files* nil)
                           (tbnl::*session* nil)
                           (transfer-encodings (cdr (assoc* :transfer-encoding headers-in))))
                      ;; instantiation must follow this order as any errors are recorded as side-effects on the response
                      ;; return code, which must be checked...
                      (setf (http:response-request tbnl::*reply*) tbnl::*request*)
                      (setf (http:request-response tbnl::*request*) tbnl::*reply*)
                      (when transfer-encodings
                        (setq transfer-encodings
                              (split "\\s*,\\s*" transfer-encodings))
                        (when (member "chunked" transfer-encodings :test #'equalp)
                          (cond ((acceptor-input-chunking-p acceptor)
                                 ;; turn chunking on before we read the request body
                                 (setf (chunked-stream-input-chunking-p input-stream) t))
                                (t (http:bad-request "Client tried to use chunked encoding, but acceptor is configured to not use it.")))))
                      (if (eql +http-ok+ (return-code tbnl::*reply*))
                          ;; if initialization succeeded, process
                          (with-acceptor-request-count-incremented (acceptor)
                            ;; at this point thread counts as active wrt eventual soft shutdown (see stop)
                            (catch 'request-processed
                              (http::respond-to-connection acceptor tbnl::*request* tbnl::*reply*)))
                          ;; otherwise, report the error
                          (http:error :code (return-code tbnl::*reply*)))
                      ;; iff chunking, emit the last chunk and then the terminating chunk
                      (force-output output-stream)
                      ;; record content disposition filter in the output strram
                      (when (chunga:chunked-stream-output-chunking-p output-stream)
                        (setf (chunga:chunked-stream-output-chunking-p output-stream) nil))
                      (close output-stream)
                      ;;(reset-connection-stream *acceptor* (http:response-content-stream tbnl::*reply*))
                      ;; access log message
                      (acceptor-log-access acceptor :return-code (http:response-status-code tbnl::*reply*)))
                    ;; synchronize on the underlying stream
                    ;; (finish-output acceptor-stream)
                    (when tbnl::*close-hunchentoot-stream*
                      (return)))))))
        (close acceptor-stream :abort t)
        (setq socket-stream nil))
      (when socket-stream
        ;; as we are at the end of the request here, we ignore all
        ;; errors that may occur while flushing and/or closing the
        ;; stream.
        ;; as the socket stream is still bound, an error occurred - do not flush, just close
        (ignore-errors*
         (close socket-stream :abort t))))))


;;; adapted from hunchensocket:acceptor-dispatch-request
(defmethod http::respond-to-connection ((acceptor ws:acceptor) request response)
  "Attempt WebSocket connection, else fall back to HTTP"
    (cond ((and (member "upgrade" (split "\\s*,\\s*" (header-in* :connection))
                        :test #'string-equal)
                (string-equal "websocket" (header-in* :upgrade)))
           (hunchensocket::handle-handshake acceptor request response)
           ;; if that returns, the headers have been configured for a handshake reply
           (let ((stream (http:response-content-stream response))
                 (ws:*request* request)
                 (ws:*response* response))
             (http:send-headers response)
             (http::finish-header-output stream)
             (force-output stream)
             (catch 'websocket-done
               (handler-bind ((error #'(lambda (e)
                                         (maybe-invoke-debugger e)
                                         (log-message* :error "Error: ~a" e)
                                         (throw 'websocket-done nil))))
                 (let ((ws:*acceptor* acceptor))
                   (ws::websocket-request-loop acceptor request response))))))
          (t
           (let ((http:*request* tbnl::*request*)
                 (http:*response* tbnl::*reply*))
             ;; Client is not requesting websockets, let Hunchentoot do its HTTP
             ;; thing undisturbed.
             (http::respond-to-request acceptor request response)))))
