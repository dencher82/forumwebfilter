package telran.ashkelon2020.accounting.service;

import telran.ashkelon2020.accounting.dto.UserRegisterDto;
import telran.ashkelon2020.accounting.dto.UserResponseDto;
import telran.ashkelon2020.accounting.dto.UserUpdateDto;

public interface UserService {
	
	boolean addUser(UserRegisterDto userRegisterDto);
	
	UserResponseDto findUserByLogin(String login);
	
	UserResponseDto deleteUser(String login);
	
	UserResponseDto updateUser(String login, UserUpdateDto userUpdateDto);
	
	UserResponseDto changeRolesList(String login, String role, boolean isAddRole);
	
	UserResponseDto changeUserPassword(String user, String newPassword);

}
