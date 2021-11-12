package com.watacodelabs.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.watacodelabs.springsecurity.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEnconder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEnconder) {
        this.passwordEnconder = passwordEnconder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                    "lucidio",
                    passwordEnconder.encode("pass"),
                    STUDENT.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
                    ),
                new ApplicationUser(
                    "admin",
                    passwordEnconder.encode("admin"),
                    ADMIN.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
                    ),
                new ApplicationUser(
                    "adminTrainee",
                    passwordEnconder.encode("admin"),
                    ADMINTRAINEE.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
                    )
        );

        return applicationUsers;
    }
}
