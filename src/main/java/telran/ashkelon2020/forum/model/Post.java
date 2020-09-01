package telran.ashkelon2020.forum.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@AllArgsConstructor
@Document(collection = "posts")
@EqualsAndHashCode(of = { "id" })
public class Post {
	String id;
	@Setter
	String title;
	@Setter
	String content;
	@Setter
	String author;
	LocalDateTime dateCreated = LocalDateTime.now();
	@Setter
	Set<String> tags = new HashSet<>();
	int likes;
	List<Comment> comments = new ArrayList<>();
	
	public Post(String title, String content, String author, Set<String> tags) {
//		this.id = author + System.currentTimeMillis(); // mongoDB will generate Id by yourself
		this.title = title;
		this.content = content;
		this.author = author;
		dateCreated = LocalDateTime.now();
		this.tags = tags;
		likes = 0;
		comments = new ArrayList<Comment>();
	}
	
	/**
	 * The method adds a tag in set of tags
	 * 
	 * @param tag
	 * @return true, if tag was added in set of tags
	 */
	public boolean addTag(String tag) {
		return tags.add(tag);
	}
	
	/**
	 * The method removes a tag from set of tags
	 * 
	 * @param tag
	 * @return null or tag, if it exists
	 */
	public boolean removeTag(String tag) {
		return tags.remove(tag);
	}
	
	/**
	 * The method returns whether there is a tag
	 * 
	 * @param tag
	 * @return true, if tag exists
	 */
	public boolean isTag(String tag) {
		return tags.contains(tag);
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
	
	/**
	 * The method adds a comment in list of comments
	 * 
	 * @param comment
	 */
	public void addComment(Comment comment) {
		comments.add(comment);
	}
	
	/**
	 * The method removes a comment in list of comments
	 * 
	 * @param comment
	 * @return
	 */
	public boolean removeComment(Comment comment) {
		return comments.remove(comment);
	}

}
