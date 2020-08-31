package telran.ashkelon2020.accounting.dto;

import java.time.LocalDate;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponseDto {
	String login;
	String firstName;
	String lastName;
	LocalDate expDate;
	Set<String> roles;
	
}
