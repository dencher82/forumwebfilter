package telran.ashkelon2020.accounting.service.security.filter;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.service.security.AccountSecurity;

@Service
@Order(40)
public class ValidateUserFilter implements Filter {
	
	@Autowired
	AccountSecurity securityService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		String method = request.getMethod();
		String headerXPassword = request.getHeader("X-Password");
		if (checkPathMethodAndHeader(path, method, headerXPassword)) {
			String token = request.getHeader("Authorization");
			String login = securityService.getLogin(token);
			String[] pathElements = path.split("/");
			String user = pathElements[3];
			if (!user.equals(login)) {
				response.sendError(403);
				return;
			}
		}		
		chain.doFilter(request, response);
	}

	private boolean checkPathMethodAndHeader(String path, String method, String header) {
		return path.matches("^/account/user/\\w+[^/]\\w+") && header == null;
	}

}
