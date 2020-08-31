package telran.ashkelon2020.accounting.service;

import java.time.LocalDateTime;

import org.mindrot.jbcrypt.BCrypt;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.dto.UserRegisterDto;
import telran.ashkelon2020.accounting.dto.UserResponseDto;
import telran.ashkelon2020.accounting.dto.UserUpdateDto;
import telran.ashkelon2020.accounting.dto.exception.UnauthorizedException;
import telran.ashkelon2020.accounting.dto.exception.UserNotFoundException;
import telran.ashkelon2020.accounting.model.User;

@Component
@ManagedResource
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepositoryMongoDB userRepository;

	@Autowired
	ModelMapper modelMapper;

	@Value("${expdate.value}")
	private long period;

	@Value("${default.role}")
	private String defaultUser;
	
	@ManagedAttribute // can see this attribute in Runtime (jconsole)
	public long getPeriod() {
		return period;
	}
	
	@ManagedAttribute // can change this attribute in Runtime (jconsole)
	public void setPeriod(long period) {
		this.period = period;
	}

	public String getDefaultUser() {
		return defaultUser;
	}

	public void setDefaultUser(String defaultUser) {
		this.defaultUser = defaultUser;
	}

	@Override
	public boolean addUser(UserRegisterDto userRegisterDto) {
		if (userRepository.existsById(userRegisterDto.getLogin())) {
			return false;
		}
		String hashPassword = BCrypt.hashpw(userRegisterDto.getPassword(), BCrypt.gensalt()); // create list of salts (hash)
		User user = modelMapper.map(userRegisterDto, User.class);
		user.setPassword(hashPassword);
		user.setExpDate(LocalDateTime.now().plusDays(period));
		user.addRole(defaultUser.toUpperCase());
		userRegisterDto.getRoles().forEach((r) -> user.addRole(r.toString()));
		userRepository.save(user);
		return true;
	}
	
	@Override
	public UserResponseDto findUserByLogin(String login) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto deleteUser(String login) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		userRepository.deleteById(login);
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto updateUser(String login, UserUpdateDto userUpdateDto) {
		User user = userRepository.findById(login).orElseThrow(() -> new UnauthorizedException());
		String firstName = userUpdateDto.getFirstName();
		if (firstName == null) {
			firstName = user.getFirstName();
		}
		user.setFirstName(firstName);
		String lastName = userUpdateDto.getLastName();
		if (lastName == null) {
			lastName = user.getLastName();
		}
		user.setLastName(lastName);
		userRepository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto changeRolesList(String login, String role, boolean isAddRole) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		if (isAddRole) {
			user.addRole(role);
		} else {
			user.removeRole(role);
		}
		userRepository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}
	
	@Override
	public UserResponseDto changeUserPassword(String login, String newPassword) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		String hashPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt());
		user.setPassword(hashPassword);
		user.setExpDate(LocalDateTime.now().plusDays(period));
		userRepository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}	

}
