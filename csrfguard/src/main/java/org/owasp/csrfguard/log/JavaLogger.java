package org.owasp.csrfguard.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JavaLogger implements ILogger {

	private static final long serialVersionUID = -4857601483759096197L;
	
	private final static Logger LOGGER=LoggerFactory.getLogger("Owasp.CsrfGuard");
	
	@Override
	public void log(String msg) {
		LOGGER.info(msg.replaceAll("(\\r|\\n)", ""));
	}

	@Override
	public void log(LogLevel level, String msg) {
		// Remove CR and LF characters to prevent CRLF injection
		String sanitizedMsg = msg.replaceAll("(\\r|\\n)", "");
		
		switch(level) {
			case Trace:
				LOGGER.trace(sanitizedMsg);
				break;
			case Debug:
				LOGGER.debug(sanitizedMsg);
				break;
			case Info:
				LOGGER.info(sanitizedMsg);
				break;
			case Warning:
				LOGGER.warn(sanitizedMsg);
				break;
			case Error:
				LOGGER.error(sanitizedMsg);
				break;
			case Fatal:
				LOGGER.error(sanitizedMsg);
				break;
			default:
				throw new RuntimeException("unsupported log level " + level);
		}
	}

	@Override
	public void log(Exception exception) {
		LOGGER.info(exception.getLocalizedMessage(), exception);
	}

	@Override
	public void log(LogLevel level, Exception exception) {
		
			switch(level) {
			case Trace:
				LOGGER.trace(exception.getLocalizedMessage(), exception);
				break;
			case Debug:
				LOGGER.debug(exception.getLocalizedMessage(), exception);
				break;
			case Info:
				LOGGER.info(exception.getLocalizedMessage(), exception);
				break;
			case Warning:
				LOGGER.warn(exception.getLocalizedMessage(), exception);
				break;
			case Error:
				LOGGER.error( exception.getLocalizedMessage(), exception);
				break;
			case Fatal:
				LOGGER.error(exception.getLocalizedMessage(), exception);
				break;
			default:
				throw new RuntimeException("unsupported log level " + level);
		}
	}
}
