package fr.algofi.hnn.springsecuritytuto.dto;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import java.util.List;

@Data
public class UserDto {

    private String email;
    private String pwd;
    private String role;

    @JsonManagedReference(value = "user-topics")
    private List<TopicDto> topics;

    @JsonManagedReference(value = "user-opinions")
    private List<OpinionDto> opinions;
}
