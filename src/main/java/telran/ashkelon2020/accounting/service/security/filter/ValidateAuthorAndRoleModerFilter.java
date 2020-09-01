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
import telran.ashkelon2020.forum.dao.ForumRepositoryMongoDB;
import telran.ashkelon2020.forum.model.Post;

@Service
@Order(60)
public class ValidateAuthorAndRoleModerFilter implements Filter {
	
	@Autowired
	AccountSecurity securityService;
	
	@Autowired
	ForumRepositoryMongoDB forumRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		String method = request.getMethod();
		if (checkPathAndMethod(path, method)) {
			String login = request.getUserPrincipal().getName();
			String id = path.split("/")[3];
			Post post = forumRepository.findById(id).orElse(null);
			if (post == null) {
				response.sendError(404, "Post not found");
				return;
			}
			String author = post.getAuthor();
			if (!(login.equals(author) || securityService.checkRole(login, "MODERATOR"))) {
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
