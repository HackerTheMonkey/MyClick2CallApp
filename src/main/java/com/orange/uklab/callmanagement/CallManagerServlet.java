package com.orange.uklab.callmanagement;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import java.util.concurrent.ConcurrentHashMap;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.sip.Address;
import javax.servlet.sip.B2buaHelper;
import javax.servlet.sip.SipApplicationSession;
import javax.servlet.sip.SipErrorEvent;
import javax.servlet.sip.SipErrorListener;
import javax.servlet.sip.SipFactory;
import javax.servlet.sip.SipServlet;
import javax.servlet.sip.SipServletRequest;
import javax.servlet.sip.SipServletResponse;
import javax.servlet.sip.SipSession;

import javax.servlet.sip.SipSession.State;
import javax.servlet.sip.SipURI;
import javax.servlet.sip.ar.SipRouteModifier;
import org.apache.log4j.Logger;

public class CallManagerServlet extends SipServlet implements SipErrorListener,
		Servlet
{
        /**
         * The forking list is implemented temporarily
         * as a Map, but later on it will be moved to a presistant database storage.
         */
        private Map<String, String[]> forkingList;
        private String preamble = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
        
	public CallManagerServlet()
        {
            this.forkingList = null;
	}
        
	@Override
	public void init(ServletConfig servletConfig) throws ServletException
        {
            super.init(servletConfig);
            this.forkingList = new ConcurrentHashMap();
//            this.forkingList.put("sip:968020@192.168.180.131;user=phone", new String[] {"sip:07800850528@192.168.0.38;user=phone"});\
            this.forkingList.put("sip:968020@192.168.0.1", new String[] {"sip:user02@192.168.0.2:4070;user=phone"});
	}
	
	@Override
	protected void doInvite(SipServletRequest req) throws ServletException, IOException
        {            
            String[] forkingUriList = this.forkingList.get(req.getTo().getURI().toString());
            System.out.println(preamble + req.getTo().getURI().toString());
            /*
             * If the forking list is set for the called number, then process the INVITE
             * message, otherwise, discard it.
             */
            if ((forkingUriList != null) && (forkingUriList.length > 0))
            {
                System.out.println(preamble + " processing INVITE message");
                B2buaHelper b2buaHelper = req.getB2buaHelper();
                String sipServletContainerFactoryAttribute = "javax.servlet.sip.SipFactory";
                SipFactory sipFactory = (SipFactory)getServletContext().getAttribute(sipServletContainerFactoryAttribute);
                /*
                 * 
                 */
                Map headers = new HashMap();
                List toHeaderSet = new ArrayList();
                toHeaderSet.add(forkingUriList[0]);
                headers.put("To", toHeaderSet);
                /*
                 * Before forking the INVITE message, we need to inform the calling party
                 * about the progressing processing of the call, that will be achieved via
                 * sending a TRYING response back to the calling party.
                 *
                 * Note: It seems that the TRYING response message is somehow optional, we need
                 * to check the RFC3261 for that.
                 */
                SipServletResponse tryingResponse = req.createResponse(SipServletResponse.SC_TRYING);
                tryingResponse.send();
                /*
                 * Create the forking request, a new SipSession will be created
                 * for this forked request that share the same SipApplicationSession
                 * with the original request. To keep track of the original request, we need
                 * to store the original session inside it.(or store the whole original request object in it.)
                 */
                SipServletRequest forkedRequest = b2buaHelper.createRequest(req, true, headers);
                SipURI sipRequestUri = (SipURI)sipFactory.createURI(forkingUriList[0]);
                forkedRequest.setRequestURI(sipRequestUri);
                /*
                 * Get the session created for the forked request, and store
                 * the original request session in it as an attribute for later
                 * retrieval.
                 */
                SipSession forkedSession = forkedRequest.getSession();
                forkedSession.setAttribute("originalRequest", req);
                /*
                 * Now we are good to go and send the forked request to where
                 * it should go...
                 */
                forkedRequest.send();
            }
            else
            {
                System.out.println(preamble + "There are no forking lists for the called number, INVITE is not forwarded");
            }
	}

        /**
         * This method is called by the doResponse method for the processing of the 2xx
         * responses.
         * @param response
         * @throws ServletException
         * @throws IOException
         */
	@Override
        protected void doSuccessResponse(SipServletResponse response)
			throws ServletException, IOException 
        {
            /**
             * Check if the method a response for a previous INVITE message,
             * and quit processing the message otherwise.
             */
            if (response.getMethod().indexOf("INVITE") != -1)
            {
                /*
                 * Send an ACK back to the called party
                 */
                SipServletRequest ackForCalled = response.createAck();
                ackForCalled.send();
                System.out.println(preamble + "Sending ACK to the called party");
                /*
                 * Sending a 200OK response back to the caller party
                 */
                SipServletRequest originalRequest = (SipServletRequest)response.getSession().getAttribute("originalRequest");
                SipServletResponse okResponseToCaller = originalRequest.createResponse(200);
                /*
                 * Now we need to copy the content of the message received form the called party 
                 * to the calling party, this is the session description content, SDP.
                 */
                okResponseToCaller.setContentLength(response.getContentLength());
                if (response.getContent() != null && response.getContentType() != null)
                {
                    okResponseToCaller.setContent(response.getContent(), response.getContentType());
                }
                // Now we shall send the 200 OK message to the calling party
                System.out.println(preamble + "Sending a 200 OK resoponse to the calling party");
                okResponseToCaller.send();                
            }
            /*
             * Check if the response is related to a previous BYE request, and simply
             * invalidate the requester session, assuming that the other end of the session is already
             * invalidated when the other pary sent a BYE request. This will also invlove the invalidation
             * of the whole application session as well.
             */
            if (response.getMethod().indexOf("BYE") != -1)
            {
                /*
                 * Get the session corresponds to the BYE response and
                 * invalidate it.
                 */
                SipSession byeResponseSession = response.getSession(false);
                if ((byeResponseSession != null) && (byeResponseSession.isValid()))
                {
                    byeResponseSession.invalidate();
                }
                /*
                 * Get the whole application session and invalidate
                 * it as well.
                 */
                SipApplicationSession appSession = response.getApplicationSession(false);
                if ((appSession != null) && (appSession.isValid()))
                {
                    appSession.invalidate();
                }
            }
	}

        /**
         * This method will be called by the doResponse method for the processing
         * of the 1xx response messages
         * @param resp
         * @throws javax.servlet.ServletException
         * @throws java.io.IOException
         */
        @Override
        protected void doProvisionalResponse(SipServletResponse resp)
            throws javax.servlet.ServletException, java.io.IOException
        {
            System.out.println(preamble + "Received a ringing response for status code of " + resp.getStatus());
            /**
             * Here we need to retrieve the original request that we have already stored inside the forked invite
             * message, and this will help us construct a ringing response back to the caller.
             */
            SipServletRequest originalRequest = (SipServletRequest)resp.getSession().getAttribute("originalRequest");
            SipServletResponse ringingResponse = originalRequest.createResponse(SipServletResponse.SC_RINGING);
            ringingResponse.send();
            System.out.println(preamble + "The ringing response has been sent.");
        }

    public void noAckReceived(SipErrorEvent ee) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void noPrackReceived(SipErrorEvent ee) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * When handling BYE requests, we need to confirm the request with a 200 OK
     * response back to the requesting party (whether being calling or called party, which
     * depends on who hangs up first during an actibe call session.
     * On the other hand, we have to generate another request for the other leg of the
     * call and send a BYE request to it, the responses that the client generates for this
     * BYE requet need to be handled by the doSuccessResponse accordingly by invalidating the
     * session that is requested to be terminated.
     */
    protected void doBye(SipServletRequest req)
        throws javax.servlet.ServletException,java.io.IOException
    {
        /*
         * Sending a 200 OK back to the requesting party
         */
        SipServletResponse byeResponseToRequestor = req.createResponse(SipServletResponse.SC_OK);
        byeResponseToRequestor.send();
        /*
         * Now we need to retrieve the SipSession associated with rhe received request, and then
         * we need to get any linked session with that session and use it to construct a BYE request to
         * that end of the call. The original request session need to be invalidated.
         */
        SipSession byeRequestorSession = req.getSession();
        B2buaHelper b2buaHelper = req.getB2buaHelper();
        SipSession theOtherPartySession = b2buaHelper.getLinkedSession(byeRequestorSession);
        SipServletRequest byeRequestToTheOtherEnd = theOtherPartySession.createRequest("BYE");
        byeRequestToTheOtherEnd.send();
        /*
         * The BYE requestor session is to be invalidated here, as an 200 OK response has been already
         * sent. The other end session will be invalidated upon the reception of the 200 OK from the
         * other end of the call.
         */
        if ((byeRequestorSession != null) && (byeRequestorSession.isValid()))
        {
            byeRequestorSession.invalidate();
        }        
    }

    /**
     * The handling of the Cancel requests is a bit tricky, here is the story:
     * We are assuming here that the Cancel request is always generated by the
     * calling party to cancel the INVITE request it has sent before the called
     * party picks up (sends a 200 OK response. From the B2B side, we need to
     * cancel the request that we have forked to the called party.
     * Thus, to do that we need to get the session associated with the Cancel
     * request, then using the B2bHelper we can get the session linked and associated
     * with that session under one SipApplicationSession and then we need to retrieve the
     * original request we have stored in the forked session. Having that done, we
     * need to get the forked request (which is the request that we need to cancel) that
     * is generated basing on the parameters of the orginal request (except for modifying
     * the To field) and then create a cancel request basing on it. and afterwards we need to
     * send the cancel request to the other end of the call.
     * @param req
     * @throws javax.servlet.ServletException
     * @throws java.io.IOException
     */
    protected void doCancel(SipServletRequest req)
        throws javax.servlet.ServletException,java.io.IOException
    {
        SipSession session = req.getSession();
        B2buaHelper b2buaHelper = req.getB2buaHelper();
        SipSession theOtherSession = b2buaHelper.getLinkedSession(session);
        SipServletRequest originalRequest = (SipServletRequest)theOtherSession.getAttribute("originalRequest");
        SipServletRequest cancelRequest = b2buaHelper.getLinkedSipServletRequest(originalRequest).createCancel();
        cancelRequest.send();
    }

    protected void doRegister(SipServletRequest req)
       throws javax.servlet.ServletException,java.io.IOException
    {
        System.out.println(preamble + "Processing registration request from " + req.getFrom().toString());
        SipServletResponse registrationResponse = req.createResponse(SipServletResponse.SC_OK);
        Address address = req.getAddressHeader("Contact");
        registrationResponse.setAddressHeader("Contact", address);
        registrationResponse.send();
    }
}