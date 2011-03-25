/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric.sheridan@owasp.org), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.csrfguard.http.InterceptRedirectResponse;
import org.owasp.csrfguard.http.MultipartHttpServletRequest;

public final class CsrfGuardFilter implements Filter {
	
	private FilterConfig filterConfig = null;
	
	@Override
	public void destroy() {
		/** nothing to do **/
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		/** only work with HttpServletRequest objects **/
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest)request;
			InterceptRedirectResponse redirectResponse = new InterceptRedirectResponse((HttpServletResponse)response);
			HttpSession session = httpRequest.getSession(true);
			
			CsrfGuard csrfGuard = (CsrfGuard)session.getAttribute(CsrfGuard.SESSION_KEY);
			csrfGuard.getLogger().log(String.format("CsrfGuard analyzing request %s", httpRequest.getRequestURI()));
			
			if(MultipartHttpServletRequest.isMultipartRequest(httpRequest)) {
				httpRequest = new MultipartHttpServletRequest(httpRequest);
			}
			
			if(session.isNew()) {
				csrfGuard.writeLandingPage(httpRequest, redirectResponse);
			} else if(csrfGuard.isValidRequest(httpRequest, redirectResponse)) {
				filterChain.doFilter(httpRequest, redirectResponse);
			} else {
				/** invalid request - nothing to do - actions already executed **/
			}
			
			/** update tokens **/
			csrfGuard.updateTokens(httpRequest);
			
			/** ensure token included in redirects **/
			if(redirectResponse.getLocation() != null) {
				String location = redirectResponse.getLocation();
				
				if(!location.contains("://") && !csrfGuard.isUnprotectedPage(location)) {
					if(!location.startsWith("/")) {
						location = filterConfig.getServletContext().getContextPath() + "/" + location;
					}
					
					String tokenValue = csrfGuard.getTokenValue(httpRequest, location);
					redirectResponse.sendRedirect(location, csrfGuard.getTokenName(), tokenValue);
				} else {
					csrfGuard.getLogger().log(String.format("CsrfGuard skipping redirect token injection for location %s", location));
					
					redirectResponse.getResponse().sendRedirect(location);
				}
			}
			
		} else {
			filterConfig.getServletContext().log(String.format("[WARNING] CsrfGuard does not know how to work with requests of class %s ", request.getClass().getName()));
			
			filterChain.doFilter(request, response);
		}
	}
	
	@Override
	public void init(@SuppressWarnings("hiding") FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}
	
}
