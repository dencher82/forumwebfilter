package telran.ashkelon2020.accounting.service.security;

public interface AccountSecurity {
	
	String getLogin(String token);
	
	boolean checkExpDate(String login);

	boolean checkRole(String login, String role);
	
	boolean isBanned(String login);
	
	String addUser(String sessionId, String login);
	
	String getUser(String sessionId);
	
	String removeUser(String sessionId);
	
}
