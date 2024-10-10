package fr.algofi.hnn.springsecuritytuto.dao;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "USERS")
@Getter @Setter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;

    private String pwd;

    private String role;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "user")
    private List<Topic> topics = new ArrayList<>();

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "user")
    private List<Opinion> opinions = new ArrayList<>();
}
