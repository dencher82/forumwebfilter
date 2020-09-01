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
@Order(60)
public class ValidateRoleUserModerFilter implements Filter {
	
	@Autowired
	AccountSecurity securityService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		String method = request.getMethod();
		if (checkPathAndMethod(path, method)) {
			String token = request.getHeader("Authorization");
			String login = securityService.getLogin(token);
			if (!securityService.checkRole(login, "USER") || !securityService.checkRole(login, "MODERATOR")) {
				response.sendError(403, "Not enough rights");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPathAndMethod(String path, String method) {
		int size = path.split("/").length;
		boolean res = ("PUT".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) && size == 4;
		return res;
	}
	
	
}
