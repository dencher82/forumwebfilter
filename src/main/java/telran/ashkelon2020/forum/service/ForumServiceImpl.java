package telran.ashkelon2020.forum.service;

import java.util.Set;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.forum.dao.ForumRepositoryMongoDB;
import telran.ashkelon2020.forum.dto.CommentDto;
import telran.ashkelon2020.forum.dto.DatePeriodDto;
import telran.ashkelon2020.forum.dto.MessageDto;
import telran.ashkelon2020.forum.dto.PostDto;
import telran.ashkelon2020.forum.dto.PostResponseDto;
import telran.ashkelon2020.forum.dto.exception.PostNotFoundException;
import telran.ashkelon2020.forum.model.Comment;
import telran.ashkelon2020.forum.model.Post;

@Component
public class ForumServiceImpl implements ForumService {
	
	@Autowired
	ForumRepositoryMongoDB forumRepository;
	
	@Autowired
	ModelMapper modelMapper;

	@Override
	public PostResponseDto addPost(String author, PostDto postDto) {
		Post post = modelMapper.map(postDto, Post.class);
		post.setAuthor(author);
		Post res = forumRepository.save(post);
		return modelMapper.map(res, PostResponseDto.class);
	}

	@Override
	public PostResponseDto findPostById(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public PostResponseDto deletePost(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		forumRepository.deleteById(id);
		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public PostResponseDto updatePost(String id, PostDto postDto) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		String title = postDto.getTitle();
		if (title == null) {
			title = post.getTitle();
		}
		String content = postDto.getContent();
		if (content == null) {
			content = post.getContent();
		}
		Set<String> tags = postDto.getTags();
		if (tags == null) {
			tags = post.getTags();
		}
		post.setTitle(title);
		post.setContent(content);
		post.setTags(tags);
		forumRepository.save(post);
		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public boolean addLikeToPost(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		post.addLike();
		forumRepository.save(post);
		return true;
	}

	@Override
	public PostResponseDto addCommentToPost(String id, String user, MessageDto messageDto) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		Comment comment = modelMapper.map(messageDto, Comment.class);
		comment.setUser(user);
		post.addComment(comment);
		forumRepository.save(post);
		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public Iterable<PostResponseDto> findPostsByAuthor(String author) {
		return forumRepository.findPostsByAuthor(author)
				.map(p -> modelMapper.map(p, PostResponseDto.class))
				.collect(Collectors.toList());
	}

	@Override
	public Iterable<PostResponseDto> findPostsByTags(Set<String> tags) {
		return forumRepository.findPostsByTagsContaining(tags)
				.map(s -> modelMapper.map(s, PostResponseDto.class))
				.collect(Collectors.toList());
	}
	
	@Override
	public Iterable<PostResponseDto> findPostsByDates(DatePeriodDto datePeriodDto) {
		return forumRepository.findByDateCreatedBetween(datePeriodDto.getDateFrom(), datePeriodDto.getDateTo())
				.map(s -> modelMapper.map(s, PostResponseDto.class))
				.collect(Collectors.toList());
	}

	@Override
	public Iterable<CommentDto> findAllPostComments(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		return post.getComments().stream()
				.map(c -> modelMapper.map(c, CommentDto.class))
				.collect(Collectors.toList());
	}

	@Override
	public Iterable<CommentDto> findAllPostCommentsByAuthor(String id, String author) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		return post.getComments().stream()
				.filter(c -> author.equals(c.getUser()))
				.map(c -> modelMapper.map(c, CommentDto.class))
				.collect(Collectors.toList());
	}

}
