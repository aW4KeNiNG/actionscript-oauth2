package com.adobe.protocols.oauth2
{
    import com.adobe.protocols.oauth2.event.GetAccessTokenEvent;
    import com.adobe.protocols.oauth2.event.RefreshAccessTokenEvent;
    import com.adobe.protocols.oauth2.grant.AuthorizationCodeGrant;
    import com.adobe.protocols.oauth2.grant.IGrantType;
    import com.adobe.protocols.oauth2.grant.ImplicitGrant;
    import com.adobe.protocols.oauth2.grant.ResourceOwnerCredentialsGrant;
    import com.adobe.serialization.json.JSONParseError;

    import flash.events.ErrorEvent;
    import flash.events.Event;
    import flash.events.EventDispatcher;
    import flash.events.IOErrorEvent;
    import flash.events.SecurityErrorEvent;
    import flash.net.Socket;
    import flash.net.URLLoader;
    import flash.net.URLRequest;
    import flash.net.URLRequestMethod;
    import flash.net.URLVariables;
    import flash.net.navigateToURL;

    import org.as3commons.logging.api.ILogger;
    import org.as3commons.logging.api.LOGGER_FACTORY;
    import org.as3commons.logging.api.getLogger;
    import org.as3commons.logging.setup.LevelTargetSetup;
    import org.as3commons.logging.setup.LogSetupLevel;
    import org.as3commons.logging.setup.target.IFormattingLogTarget;
    import org.as3commons.logging.setup.target.TraceTarget;

    /**
	 * Event that is broadcast when results from a <code>getAccessToken</code> request are received.
	 * 
	 * @eventType com.adobe.protocols.oauth2.event.GetAccessTokenEvent.TYPE
	 * 
	 * @see #getAccessToken()
	 * @see com.adobe.protocols.oauth2.event.GetAccessTokenEvent
	 */
	[Event(name="getAccessToken", type="com.adobe.protocols.oauth2.event.GetAccessTokenEvent")]
	
	/**
	 * Event that is broadcast when results from a <code>refreshAccessToken</code> request are received.
	 * 
	 * @eventType com.adobe.protocols.oauth2.event.RefreshAccessTokenEvent.TYPE
	 * 
	 * @see #refreshAccessToken()
	 * @see com.adobe.protocols.oauth2.event.RefreshAccessTokenEvent
	 */
	[Event(name="refreshAccessToken", type="com.adobe.protocols.oauth2.event.RefreshAccessTokenEvent")]
	
	/**
	 * Utility class the encapsulates APIs for interaction with an OAuth 2.0 server.
	 * Implemented against the OAuth 2.0 v2.15 specification.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15
	 * 
	 * @author Charles Bihis (www.whoischarles.com)
	 */
	public class OAuth2 extends EventDispatcher
	{
		private static const log:ILogger = getLogger(OAuth2);
		
		private var grantType:IGrantType;
		private var authEndpoint:String;
		private var tokenEndpoint:String;
		private var logTarget:IFormattingLogTarget;
        private var localServer:LocalServer;
		
		
		/**
		 * Constructor to create a valid OAuth2 client object.
		 * 
		 * @param authEndpoint The authorization endpoint used by the OAuth 2.0 server
		 * @param tokenEndpoint The token endpoint used by the OAuth 2.0 server
		 * @param logLevel (Optional) The new log level for the logger to use
		 */
		public function OAuth2(authEndpoint:String, tokenEndpoint:String, logLevel:LogSetupLevel = null, logTarget:IFormattingLogTarget = null)
		{
			// save endpoint properties
			this.authEndpoint = authEndpoint;
			this.tokenEndpoint = tokenEndpoint;
			
			// set up logging
			this.logTarget = logTarget ? logTarget : new TraceTarget();
			logTarget.format = "{date} {time} [{logLevel}] {name} {message}";
			LOGGER_FACTORY.setup = new LevelTargetSetup(logTarget, (logLevel == null) ? LogSetupLevel.NONE : logLevel);
		} // OAuth2

        public function dispose():void
        {
            if(localServer)
            {
                localServer.close();
                localServer = null;
            }
        }

		/**
		 * Initiates the access token request workflow with the proper context as
		 * described by the passed-in grant-type object.  Upon completion, will
		 * dispatch a <code>GetAccessTokenEvent</code> event.
		 * 
		 * @param grantType An <code>IGrantType</code> object which represents the desired workflow to use when requesting an access token
		 * 
		 * @see com.adobe.protocols.oauth2.grant.IGrantType
		 * @see com.adobe.protocols.oauth2.event.GetAccessTokenEvent#TYPE
		 */
		public function getAccessToken(grantType:IGrantType):void
		{
			if (grantType is AuthorizationCodeGrant)
			{
				log.info("Initiating getAccessToken() with authorization code grant type workflow");
				getAccessTokenWithAuthorizationCodeGrant(grantType as AuthorizationCodeGrant);
			}  // if statement
			else if (grantType is ImplicitGrant)
			{
				log.info("Initiating getAccessToken() with implicit grant type workflow");
				getAccessTokenWithImplicitGrant(grantType as ImplicitGrant);
			}  // else-if statement
			else if (grantType is ResourceOwnerCredentialsGrant)
			{
				log.info("Initiating getAccessToken() with resource owner credentials grant type workflow");
				getAccessTokenWithResourceOwnerCredentialsGrant(grantType as ResourceOwnerCredentialsGrant);
			}  // else-if statement
		}  // getAccessToken
		
		/**
		 * Initiates request to refresh a given access token.  Upon completion, will dispatch
		 * a <code>RefreshAccessTokenEvent</code> event.  On success, a new refresh token may
		 * be issues, at which point the client should discard the old refresh token with the
		 * new one.
		 * 
		 * @param refreshToken A valid refresh token received during last request for an access token
		 * @param clientId The client identifier
		 * @param clientSecret The client secret
		 * 
		 * @see com.adobe.protocols.oauth2.event.RefreshAccessTokenEvent#TYPE
		 */
		public function refreshAccessToken(refreshToken:String, clientId:String, clientSecret:String, scope:String = null):void
		{
			// create result event
			var refreshAccessTokenEvent:RefreshAccessTokenEvent = new RefreshAccessTokenEvent();
			
			// set up URL request
			var urlRequest:URLRequest = new URLRequest(tokenEndpoint);
			var urlLoader:URLLoader = new URLLoader();
			urlRequest.method = URLRequestMethod.POST;
			
			// define POST parameters
			var urlVariables : URLVariables = new URLVariables();  
			urlVariables.grant_type = OAuth2Const.GRANT_TYPE_REFRESH_TOKEN; 
			urlVariables.client_id = clientId;
			urlVariables.client_secret = clientSecret;
			urlVariables.refresh_token = refreshToken;
			
			// define optional scope parameter only when scope not null
			if(scope !== null)
			{
				urlVariables.scope = scope;
			}
			
			urlRequest.data = urlVariables;
			
			// attach event listeners
			urlLoader.addEventListener(Event.COMPLETE, onRefreshAccessTokenResult);
			urlLoader.addEventListener(IOErrorEvent.IO_ERROR, onRefreshAccessTokenError);
			urlLoader.addEventListener(SecurityErrorEvent.SECURITY_ERROR, onRefreshAccessTokenError);
			
			// make the call
			try
			{
				urlLoader.load(urlRequest);
			}  // try statement
			catch (error:Error)
			{
				log.error("Error loading token endpoint \"" + tokenEndpoint + "\"");
			}  // catch statement
			
			function onRefreshAccessTokenResult(event:Event):void
			{
				try
				{
					var response:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
					log.debug("Access token: " + response.access_token);
					refreshAccessTokenEvent.parseAccessTokenResponse(response);
				}  // try statement
				catch (error:JSONParseError)
				{
					refreshAccessTokenEvent.errorCode = "com.adobe.serialization.json.JSONParseError";
					refreshAccessTokenEvent.errorMessage = "Error parsing output from refresh access token response";					
				}  // catch statement
				
				dispatchEvent(refreshAccessTokenEvent);
			}  // onRefreshAccessTokenResult
			
			function onRefreshAccessTokenError(event:Event):void
			{
				log.error("Error encountered during refresh access token request: " + event);
				
				try
				{
					var error:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
					refreshAccessTokenEvent.errorCode = error.error;
					refreshAccessTokenEvent.errorMessage = error.error_description;
				}  // try statement
				catch (error:JSONParseError)
				{
					refreshAccessTokenEvent.errorCode = "Unknown";
					refreshAccessTokenEvent.errorMessage = "Error encountered during refresh access token request.  Unable to parse error message.";
				}  // catch statement
				
				dispatchEvent(refreshAccessTokenEvent);
			}  // onRefreshAccessTokenError
		}  // refreshAccessToken
		
		/**
		 * Modifies the log level of the logger at runtime.
		 * 
		 * <p>By default, logging is turned off.  Passing in any value will modify the logging level
		 * of the application.  This method can accept any of the following values...</p>
		 * 
		 * <ul>
		 * 	<li>LogSetupLevel.NONE</li>
		 *  <li>LogSetupLevel.FATAL</li>
		 *  <li>LogSetupLevel.FATAL_ONLY</li>
		 *  <li>LogSetupLevel.ERROR</li>
		 *  <li>LogSetupLevel.ERROR_ONLY</li>
		 *  <li>LogSetupLevel.WARN</li>
		 *  <li>LogSetupLevel.WARN_ONLY</li>
		 *  <li>LogSetupLevel.INFO</li>
		 *  <li>LogSetupLevel.INFO_ONLY</li>
		 *  <li>LogSetupLevel.DEBUG</li>
		 *  <li>LogSetupLevel.DEBUG_ONLY</li>
		 *  <li>LogSetupLevel.ALL</li>
		 * </ul>
		 * 
		 * @param logLevel The new log level for the logger to use
		 * 
		 * @see org.as3commons.logging.setup.LogSetupLevel.NONE
		 * @see org.as3commons.logging.setup.LogSetupLevel.FATAL
		 * @see org.as3commons.logging.setup.LogSetupLevel.FATAL_ONLY
		 * @see org.as3commons.logging.setup.LogSetupLevel.ERROR
		 * @see org.as3commons.logging.setup.LogSetupLevel.ERROR_ONLY
		 * @see org.as3commons.logging.setup.LogSetupLevel.WARN
		 * @see org.as3commons.logging.setup.LogSetupLevel.WARN_ONLY
		 * @see org.as3commons.logging.setup.LogSetupLevel.INFO
		 * @see org.as3commons.logging.setup.LogSetupLevel.INFO_ONLY
		 * @see org.as3commons.logging.setup.LogSetupLevel.DEBUG
		 * @see org.as3commons.logging.setup.LogSetupLevel.DEBUG_ONLY
		 * @see org.as3commons.logging.setup.LogSetupLevel.ALL
		 */
		public function setLogLevel(logLevel:LogSetupLevel):void
		{
			LOGGER_FACTORY.setup = new LevelTargetSetup(logTarget, logLevel);
		}  // setLogLevel

		/**
		 * @private
		 * 
		 * Helper function that completes get-access-token request using the authorization code grant type.
		 */
		private function getAccessTokenWithAuthorizationCodeGrant(authorizationCodeGrant:AuthorizationCodeGrant):void
		{
            var authCodeReady:Boolean = false;

			// create result event
			var getAccessTokenEvent:GetAccessTokenEvent = new GetAccessTokenEvent();

            if(authorizationCodeGrant.redirectUri.indexOf("localhost"))
            {
                if(localServer)
                    localServer.close();

                localServer = new LocalServer();
                localServer.listen(parseInt(authorizationCodeGrant.redirectUri.split(":").pop()));
                localServer.addEventListener(ErrorEvent.ERROR, onError);
                localServer.addEventListener(LocalServer.EVENT_DATA_RECEIVED, function(e:SocketEvent):void {
                    var socket:Socket = e.socket;
                    var bufferString:String = e.data.toString();
                    var headerCheck:Number = bufferString.search(/\r?\n\r?\n/);
                    if (headerCheck != -1)
                    {
                        localServer.removeEventListener(LocalServer.EVENT_DATA_RECEIVED, arguments.callee);

                        var headerString:String = bufferString.substring(0, headerCheck);
                        // Parse the request signature.
                        var initialRequestSignature:String = headerString.substring(0, headerString.search(/\r?\n/));
                        var initialRequestSignatureComponents:Array = initialRequestSignature.split(" ");
//                        var method:String = initialRequestSignatureComponents[0];
                        var serverAndPath:String = initialRequestSignatureComponents[1];
                        serverAndPath = serverAndPath.replace(/^http(s)?:\/\//, "");
                        var path:String = serverAndPath.substring(serverAndPath.indexOf("/"), serverAndPath.length);
                        checkLocation(path);

                        localServer.send(socket, "HTTP/1.0 200 OK\n\n");
                    }
                });
            }
			
			// start the auth process
			var startTime:Number = new Date().time;
			log.info("Loading auth URL: " + authorizationCodeGrant.getFullAuthUrl(authEndpoint));
			navigateToURL(new URLRequest(authorizationCodeGrant.getFullAuthUrl(authEndpoint)));

            function onError(e:ErrorEvent):void
            {
                log.error(e.errorID + ": " + e.text);
                getAccessTokenEvent.errorCode = String(e.errorID);
                getAccessTokenEvent.errorMessage = e.text;
                dispatchEvent(getAccessTokenEvent);
            }
			
			function checkLocation(location:String):void
            {
				log.info("Loading URL: " + location);
                authCodeReady = true;
				if (location.indexOf(OAuth2Const.RESPONSE_PROPERTY_AUTHORIZATION_CODE) > 0)
				{
					log.info("Redirect URI encountered (" + authorizationCodeGrant.redirectUri + ").  Extracting values from path.");
					
					// determine if authorization was successful
					var queryParams:Object = extractQueryParams(location);
					var code:String = queryParams.code;		// authorization code
					if (code != null)
					{
						log.debug("Authorization code: " + code);
						getAccessTokenWithAuthCode(code);
					}  // if statement
					else
					{
						log.error("Error encountered during authorization request");
						getAccessTokenEvent.errorCode = queryParams.error;
						getAccessTokenEvent.errorMessage = queryParams.error_description;
						dispatchEvent(getAccessTokenEvent);
					}  // else statement
				}  // if statement
			}  // onLocationChange
			
			function getAccessTokenWithAuthCode(code:String):void
			{
				// set up URL request
				var urlRequest:URLRequest = new URLRequest(tokenEndpoint);
				var urlLoader:URLLoader = new URLLoader();
				urlRequest.method = URLRequestMethod.POST;
				
				// define POST parameters
				var urlVariables : URLVariables = new URLVariables();  
				urlVariables.grant_type = OAuth2Const.GRANT_TYPE_AUTHORIZATION_CODE; 
				urlVariables.code = code;
				urlVariables.redirect_uri = authorizationCodeGrant.redirectUri;
				urlVariables.client_id = authorizationCodeGrant.clientId;
				urlVariables.client_secret = authorizationCodeGrant.clientSecret;
				urlRequest.data = urlVariables;
				
				// attach event listeners
				urlLoader.addEventListener(Event.COMPLETE, onGetAccessTokenResult);
				urlLoader.addEventListener(IOErrorEvent.IO_ERROR, onGetAccessTokenError);
				urlLoader.addEventListener(SecurityErrorEvent.SECURITY_ERROR, onGetAccessTokenError);
				
				// make the call
				try
				{
					urlLoader.load(urlRequest);
				}  // try statement
				catch (error:Error)
				{
					log.error("Error loading token endpoint \"" + tokenEndpoint + "\"");
				}  // catch statement
				
				function onGetAccessTokenResult(event:Event):void
				{
					try
					{
						var response:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
						log.debug("Access token: " + response.access_token);
						getAccessTokenEvent.parseAccessTokenResponse(response);
					}  // try statement
					catch (error:JSONParseError)
					{
						getAccessTokenEvent.errorCode = "com.adobe.serialization.json.JSONParseError";
						getAccessTokenEvent.errorMessage = "Error parsing output from access token response";
					}  // catch statement
					
					dispatchEvent(getAccessTokenEvent);
				}  // onGetAccessTokenResult
				
				function onGetAccessTokenError(event:Event):void
				{
					log.error("Error encountered during access token request: " + event);
					
					try
					{
						var error:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
						getAccessTokenEvent.errorCode = error.error;
						getAccessTokenEvent.errorMessage = error.error_description;
					}  // try statement
					catch (error:JSONParseError)
					{
						getAccessTokenEvent.errorCode = "Unknown";
						getAccessTokenEvent.errorMessage = "Error encountered during access token request.  Unable to parse error message.";
					}  // catch statement
					
					dispatchEvent(getAccessTokenEvent);
				}  // onGetAccessTokenError
			}  // getAccessTokenWithAuthCode

		}  // getAccessTokenWithAuthorizationCodeGrant
		
		/**
		 * @private
		 * 
		 * Helper function that completes get-access-token request using the implicit grant type.
		 */
		private function getAccessTokenWithImplicitGrant(implicitGrant:ImplicitGrant):void
		{
            var authCodeReady:Boolean = false;

            // create result event
			var getAccessTokenEvent:GetAccessTokenEvent = new GetAccessTokenEvent();

            if(implicitGrant.redirectUri.indexOf("localhost"))
            {
                if(localServer)
                    localServer.close();

                localServer = new LocalServer();
                localServer.listen(parseInt(implicitGrant.redirectUri.split(":").pop()));
                localServer.addEventListener(ErrorEvent.ERROR, onError);
                localServer.addEventListener(LocalServer.EVENT_DATA_RECEIVED, function(e:SocketEvent):void {
                    var socket:Socket = e.socket;
                    var bufferString:String = e.data.toString();
                    var headerCheck:Number = bufferString.search(/\r?\n\r?\n/);
                    if (headerCheck != -1)
                    {
                        localServer.removeEventListener(LocalServer.EVENT_DATA_RECEIVED, arguments.callee);

                        var headerString:String = bufferString.substring(0, headerCheck);
                        // Parse the request signature.
                        var initialRequestSignature:String = headerString.substring(0, headerString.search(/\r?\n/));
                        var initialRequestSignatureComponents:Array = initialRequestSignature.split(" ");
//                        var method:String = initialRequestSignatureComponents[0];
                        var serverAndPath:String = initialRequestSignatureComponents[1];
                        serverAndPath = serverAndPath.replace(/^http(s)?:\/\//, "");
                        var path:String = serverAndPath.substring(serverAndPath.indexOf("/"), serverAndPath.length);
                        checkLocation(path);

                        localServer.send(socket, "HTTP/1.0 200 OK\n\n");
                    }
                });
            }

			// start the auth process
			log.info("Loading auth URL: " + implicitGrant.getFullAuthUrl(authEndpoint));
            navigateToURL(new URLRequest(implicitGrant.getFullAuthUrl(authEndpoint)));

            function onError(e:ErrorEvent):void
            {
                log.error(e.errorID + ": " + e.text);
                getAccessTokenEvent.errorCode = String(e.errorID);
                getAccessTokenEvent.errorMessage = e.text;
                dispatchEvent(getAccessTokenEvent);
            }

            function checkLocation(location:String):void
			{
                log.info("Loading URL: " + location);
                authCodeReady = true;
				if (location.indexOf(implicitGrant.redirectUri) == 0 && location.indexOf(OAuth2Const.RESPONSE_PROPERTY_ACCESS_TOKEN) > 0)
				{
					log.info("Redirect URI encountered (" + implicitGrant.redirectUri + ").  Extracting values from path.");

					// determine if authorization was successful
					var queryParams:Object = extractQueryParams(location);
					var accessToken:String = queryParams.access_token;
					if (accessToken != null)
					{
						log.debug("Access token: " + accessToken);
						getAccessTokenEvent.parseAccessTokenResponse(queryParams);
						dispatchEvent(getAccessTokenEvent);
					}  // if statement
					else
					{
						log.error("Error encountered during access token request");
						getAccessTokenEvent.errorCode = queryParams.error;
						getAccessTokenEvent.errorMessage = queryParams.error_description;
						dispatchEvent(getAccessTokenEvent);
					}  // else statement
				}  // if statement
			}  // onLocationChange
		}  // getAccessTokenWithImplicitGrant
		
		/**
		 * @private
		 * 
		 * Helper function that completes get-access-token request using the resource owner password credentials grant type.
		 */
		private function getAccessTokenWithResourceOwnerCredentialsGrant(resourceOwnerCredentialsGrant:ResourceOwnerCredentialsGrant):void
		{
			// create result event
			var getAccessTokenEvent:GetAccessTokenEvent = new GetAccessTokenEvent();
			
			// set up URL request
			var urlRequest:URLRequest = new URLRequest(tokenEndpoint);
			var urlLoader:URLLoader = new URLLoader();
			urlRequest.method = URLRequestMethod.POST;
			
			// define POST parameters
			var urlVariables : URLVariables = new URLVariables();  
			urlVariables.grant_type = OAuth2Const.GRANT_TYPE_RESOURCE_OWNER_CREDENTIALS;
			urlVariables.client_id = resourceOwnerCredentialsGrant.clientId;
			urlVariables.client_secret = resourceOwnerCredentialsGrant.clientSecret;
			urlVariables.username = resourceOwnerCredentialsGrant.username;
			urlVariables.password = resourceOwnerCredentialsGrant.password;
			
			// define optional scope parameter only when scope not null
			if(resourceOwnerCredentialsGrant.scope !== null)
			{
				urlVariables.scope = resourceOwnerCredentialsGrant.scope;
			}
			
			urlRequest.data = urlVariables;
			
			// attach event listeners
			urlLoader.addEventListener(Event.COMPLETE, onGetAccessTokenResult);
			urlLoader.addEventListener(IOErrorEvent.IO_ERROR, onGetAccessTokenError);
			urlLoader.addEventListener(SecurityErrorEvent.SECURITY_ERROR, onGetAccessTokenError);
			
			// make the call
			try
			{
				urlLoader.load(urlRequest);
			}  // try statement
			catch (error:Error)
			{
				log.error("Error loading token endpoint \"" + tokenEndpoint + "\"");
			}  // catch statement
			
			function onGetAccessTokenResult(event:Event):void
			{
				try
				{
					var response:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
					log.debug("Access token: " + response.access_token);
					getAccessTokenEvent.parseAccessTokenResponse(response);
				}  // try statement
				catch (error:JSONParseError)
				{
					getAccessTokenEvent.errorCode = "com.adobe.serialization.json.JSONParseError";
					getAccessTokenEvent.errorMessage = "Error parsing output from access token response";
				}  // catch statement
				
				dispatchEvent(getAccessTokenEvent);
			}  // onGetAccessTokenResult
			
			function onGetAccessTokenError(event:Event):void
			{
				log.error("Error encountered during access token request: " + event);
				
				try
				{
					var error:Object = com.adobe.serialization.json.JSON.decode(event.target.data);
					getAccessTokenEvent.errorCode = error.error;
					getAccessTokenEvent.errorMessage = error.error_description;
				}  // try statement
				catch (error:JSONParseError)
				{
					getAccessTokenEvent.errorCode = "Unknown";
					getAccessTokenEvent.errorMessage = "Error encountered during access token request.  Unable to parse error message.";
				}  // catch statement
				
				dispatchEvent(getAccessTokenEvent);
			}  // onGetAccessTokenError
		}  // getAccessTokenWithResourceOwnerCredentialsGrant
		
		/**
		 * @private
		 * 
		 * Helper function to extract query from URL and URL fragment.
		 */
		private function extractQueryParams(url:String):Object
		{
            url = decodeURIComponent(url);
			var delimiter:String = (url.indexOf("?") > 0) ? "?" : "#";
			var queryParamsString:String = url.split(delimiter)[1];
			var queryParamsArray:Array = queryParamsString.split("&");
			var queryParams:Object = new Object();
			
			for each (var queryParam:String in queryParamsArray)
			{
				var keyValue:Array = queryParam.split("=");
				queryParams[keyValue[0]] = keyValue[1];	
			}  // for loop
			
			return queryParams;
		}  // extractQueryParams



	}  // class declaration
}

import flash.events.ErrorEvent;
import flash.events.Event;
import flash.events.EventDispatcher;
import flash.events.OutputProgressEvent;
import flash.events.ProgressEvent;
import flash.events.ServerSocketConnectEvent;
import flash.net.ServerSocket;
import flash.net.Socket;
import flash.utils.ByteArray;

internal class LocalServer extends EventDispatcher
{
    static public const EVENT_DATA_RECEIVED:String = "dataReceived";

    private var _serverSocket:ServerSocket;

    public function listen(port:int):void
    {
        if(_serverSocket)
            return;

        _serverSocket = new ServerSocket();
        _serverSocket.addEventListener(ServerSocketConnectEvent.CONNECT, onConnect);

        try
        {
            _serverSocket.bind(port, "0.0.0.0");
            _serverSocket.listen();
        }
        catch (e:Error)
        {
            dispatchEvent(new ErrorEvent(ErrorEvent.ERROR, false, false, e.name + ": " + e.message, e.errorID));
        }
    }

    public function close():void
    {
        if(_serverSocket)
        {
            _serverSocket.close();
            _serverSocket = null;
        }
    }

    public function send(socket:Socket, data:String):void
    {
        try
        {
            if(socket.connected)
            {
                socket.addEventListener(OutputProgressEvent.OUTPUT_PROGRESS, onOutputProgress);
                socket.writeUTFBytes(data);
                socket.flush();
            }
        }
        catch(e:Error)
        {
            dispatchEvent(new ErrorEvent(ErrorEvent.ERROR, false, false, e.name + ": " + e.message, e.errorID));
        }

        function onOutputProgress(e:OutputProgressEvent):void
        {
            if(e.bytesPending == 0)
            {
                socket.removeEventListener(OutputProgressEvent.OUTPUT_PROGRESS, onOutputProgress);
                socket.close();
            }
        }
    }

    private function onConnect(event:ServerSocketConnectEvent):void
    {
        var clientSocket:Socket = event.socket;
        clientSocket.addEventListener(ProgressEvent.SOCKET_DATA, onClientSocketData);
        clientSocket.addEventListener(Event.CLOSE, onClose);
        var buffer:ByteArray = new ByteArray();

        function onClientSocketData(e:ProgressEvent):void
        {
            clientSocket.readBytes(buffer, buffer.length, clientSocket.bytesAvailable);
            dispatchEvent(new SocketEvent(EVENT_DATA_RECEIVED, clientSocket, buffer));
        }

        function onClose(e:Event):void
        {
            if(clientSocket.connected)
            {
                clientSocket.flush();
                clientSocket.close();
            }
        }
    }
}

internal class SocketEvent extends Event
{
    public var socket:Socket;
    public var data:ByteArray;

    public function SocketEvent(type:String, socket:Socket, data:ByteArray)
    {
        super(type);
        this.socket = socket;
        this.data = data;
    }
}