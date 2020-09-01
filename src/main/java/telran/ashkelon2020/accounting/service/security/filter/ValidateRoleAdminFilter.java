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
@Order(50)
public class ValidateRoleAdminFilter implements Filter {
	
	@Autowired
	AccountSecurity securityService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		if (checkPath(path)) {
			if (!securityService.checkRole(request.getUserPrincipal().getName(), "ADMIN")) {
				response.sendError(403, "Not enough rights");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPath(String path) {
		return path.contains("/role/");
	}
	
	
}
