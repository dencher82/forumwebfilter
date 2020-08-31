package telran.ashkelon2020.forum.model;

import java.time.LocalDateTime;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@EqualsAndHashCode(of = { "user", "dateCreated" })
public class Comment {
	@Setter
	String user;
    String message;
    LocalDateTime dateCreated = LocalDateTime.now();
    int likes;
	
    public Comment(String user, String message) {
		this.user = user;
		this.message = message;
		dateCreated = LocalDateTime.now();
		likes = 0;
	}

    /**
     * The method increases count of likes by one 
     */
	public void addLike() {
		likes++;
	}
	
	/**
	 * The method decreases count of likes by one
	 * 
	 * @return true, if reduction is possible (count of likes more then 1)
	 */
	public boolean removeLike() {
		if (likes > 0) {
			likes--;
			return true;
		}
		return false;
	}
    
}
