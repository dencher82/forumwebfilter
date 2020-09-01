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
@Order(30)
public class HaveRoleFilter implements Filter {

	@Autowired
	AccountSecurity securityService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		String method = request.getMethod();
		System.out.println(path + " " + method);
		if (checkPathAndMethod(path, method)) {
			if (securityService.isBanned(request.getUserPrincipal().getName())) {
				response.sendError(403, "The user is banned");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPathAndMethod(String path, String method) {
		boolean res = "/account/login".equalsIgnoreCase(path) && "POST".equalsIgnoreCase(method);
		res = res || ("PUT".equalsIgnoreCase(method) && path.matches("^/account/user/\\w+[^/]\\w+"));
		res = res || (path.startsWith("/forum/post/") && !"GET".equalsIgnoreCase(method));
		return res;
	}

}
