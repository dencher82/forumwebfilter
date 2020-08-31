package telran.ashkelon2020.accounting.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserChangePasswordDto {
	String login;
	String password;
	String newPassword;
	
}
