package socialMedia;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;
import socialMedia.config.SecurityConfiguration;
import socialMedia.dto.*;
import socialMedia.exception.PasswordRecoveryException;
import socialMedia.exception.RefreshTokenException;
import socialMedia.exception.RegistrationException;
import socialMedia.model.RefreshToken;
import socialMedia.model.Role;
import socialMedia.model.User;
import socialMedia.repository.RefreshTokenRepository;
import socialMedia.repository.UserRepository;
import socialMedia.service.AuthenticationService;
import socialMedia.service.CaptchaService;
import socialMedia.service.JwtService;
import socialMedia.service.UserService;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;


@SpringBootTest
@Import(SecurityConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@AutoConfigureMockMvc
@Transactional
public class McAuthServicesTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:12.3"));

    @Test
    void connectionEstablished() {
        assertThat(postgres.isCreated()).isTrue();
        assertThat(postgres.isRunning()).isTrue();
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @MockBean
    private RefreshTokenRepository refreshTokenRepository;

    @MockBean
    private UserRepository userRepository;

    @Autowired
    private AuthenticationService autoWiredAuthenticationService;

    @MockBean
    private CaptchaService captchaService;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;


    private String captcha;


    @BeforeEach
    void setUp() {
        postgres.withReuse(true);
        postgres.start();
        captcha = "qwedf";
    }


    @Test
    @DisplayName("Testing User registration for invalid captcha")
    public void registerWhenCaptchaIsInvalidTest() {
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setEmail("AMIRA@example.com");
        registrationDto.setFirstName("John");
        registrationDto.setLastName("Doe");
        registrationDto.setPassword1("123");
        registrationDto.setPassword2("123");
        when(captchaService.validateCaptcha(captcha)).thenReturn(false);
        registrationDto.setCaptchaSecret(captcha);
        Exception registrationExceptionValid = assertThrows(RegistrationException.class, () -> {
            autoWiredAuthenticationService.register(registrationDto);
        });

        assertEquals("Update the captcha!", registrationExceptionValid.getMessage());

    }


    @Test
    @DisplayName("Testing User registration for incorrect passwords")
    public void registerWhenPasswordsDoNotMatchTest() {
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setEmail("AMIRA@example.com");
        registrationDto.setFirstName("John");
        registrationDto.setLastName("Doe");
        registrationDto.setPassword1("123");
        registrationDto.setPassword2("12");
        registrationDto.setCaptchaSecret(captcha);
        when(captchaService.validateCaptcha(registrationDto.getCaptchaSecret())).thenReturn(true);
        User user = User.builder()
                .email(registrationDto.getEmail())
                .firstName(registrationDto.getFirstName())
                .lastName(registrationDto.getLastName())
                .deleted(false)
                .password(registrationDto.getPassword1())
                .roles(List.of(Role.USER))
                .build();
        when(userRepository.existsByEmail(user.getEmail())).thenReturn(false);
        Exception registrationExceptionValid = assertThrows(RegistrationException.class, () -> {
            autoWiredAuthenticationService.register(registrationDto);
        });
        assertEquals("Passwords do not match", registrationExceptionValid.getMessage());
    }


    @Test
    @DisplayName("Testing User registration with valid captcha and correct passwords")
    public void registerWhenPasswordIsCorrectTest() {
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setEmail("AMIRA@example.com");
        registrationDto.setFirstName("John");
        registrationDto.setLastName("Doe");
        registrationDto.setPassword1("123");
        registrationDto.setPassword2("123");
        when(captchaService.validateCaptcha(captcha)).thenReturn(true);
        registrationDto.setCaptchaSecret(captcha);
        registrationDto.setUuid(UUID.randomUUID());
        User user = User.builder()
                .email(registrationDto.getEmail())
                .firstName(registrationDto.getFirstName())
                .lastName(registrationDto.getLastName())
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        userService.create(user);
        autoWiredAuthenticationService.register(registrationDto);
        assertThat(user).isNotNull();
    }


    @Test
    @DisplayName("Testing For authorized User login")
    public void loginWhenUserIsAuthorized() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticateDto authenticateDto = new AuthenticateDto();
        authenticateDto.setEmail("AMIRA@example.com");
        authenticateDto.setPassword("123");
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("AMIRA@example.com")
                .firstName("DON")
                .lastName("NASHER")
                .password(passwordEncoder.encode("123"))
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        when(userRepository.findByEmail(authenticateDto.getEmail())).thenReturn(Optional.of(user));
        var jwt = jwtService.generateToken(user);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(user.getId());
        refreshToken.setToken("1231242-3DSAFGWT-GFDGASDFGS-HWGRWER3RRF");
        when(refreshTokenRepository.findByToken(refreshToken.getToken())).thenReturn(Optional.of(refreshToken));
        Cookie cookie = new Cookie("Refresh_token", refreshToken.getToken());
        Cookie cookie2 = new Cookie("Access_token", jwt);
        response.addCookie(cookie);
        response.addCookie(cookie2);
        response.addHeader("Authorization", "Bearer " + jwt);
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticateDto.getEmail(), authenticateDto.getPassword()));
        AuthenticateResponseDto authenticateResponseDto = autoWiredAuthenticationService.login(authenticateDto, response);
        assertThat(authenticateResponseDto).isNotNull();
    }

    @Test
    @DisplayName("Testing a live refreshToken")
    public void refreshTokenWhenTokenIsLive() {
        String virtualRefreshToken = UUID.randomUUID().toString();
        Cookie cookie = new Cookie("refreshToken", virtualRefreshToken);
        Cookie[] cookies = new Cookie[]{cookie};
        UUID userId = UUID.randomUUID();
        RefreshToken refreshToken = RefreshToken.builder().
                userId(userId).
                token(virtualRefreshToken)
                .expiryDate(Instant.now().plusMillis(Duration.ofMinutes(35).toMillis()))
                .build();
        refreshToken.setToken(virtualRefreshToken);
        doNothing().when(refreshTokenRepository).delete(refreshToken);
        when(refreshTokenRepository.findByToken(virtualRefreshToken)).thenReturn(Optional.of(refreshToken));
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("AMIRA")
                .lastName("NASHER")
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        jwtService.generateToken(user);
        AuthenticateResponseDto authenticateResponseDto = autoWiredAuthenticationService.refreshToken(request);
        assertThat(authenticateResponseDto).isNotNull();
    }


    @Test
    @DisplayName("Testing refreshToken when token is not available")
    public void refreshTokenWhenTokenIsNotAvailable() {
        String virtualRefreshToken = UUID.randomUUID().toString();
        Cookie cookie = new Cookie("refreshToken", virtualRefreshToken);
        Cookie[] cookies = new Cookie[]{cookie};
        UUID userId = UUID.randomUUID();
        RefreshToken refreshToken = RefreshToken.builder().
                userId(userId).
                token(virtualRefreshToken)
                .expiryDate(Instant.now().plusMillis(Duration.ofMinutes(35).toMillis()))
                .build();
        refreshToken.setToken(virtualRefreshToken);
        doNothing().when(refreshTokenRepository).delete(refreshToken);
        when(refreshTokenRepository.findByToken(cookie.getValue())).thenReturn(Optional.empty());
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("AMIRA")
                .lastName("NASHER")
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);
        when(userRepository.findById(user.getId())).thenReturn(Optional.empty());
        Exception refreshTokenException=assertThrows(RefreshTokenException.class,()-> {
            autoWiredAuthenticationService.refreshToken(request);
        });
        assertEquals("User is not logged in",refreshTokenException.getMessage());
    }

    @Test
    @DisplayName("Testing refreshToken when token is re-updated")
    public void updateRefreshTokenWhenExpired() {
        String virtualRefreshToken = UUID.randomUUID().toString();
        Cookie cookie = new Cookie("refreshToken", virtualRefreshToken);
        Cookie[] cookies = new Cookie[]{cookie};
        UUID userId = UUID.randomUUID();
        RefreshToken refreshToken = RefreshToken.builder().
                userId(userId).
                token(virtualRefreshToken)
                .expiryDate(Instant.now().plusMillis(Duration.ofMinutes(0).toMillis()))
                .build();
        refreshToken.setToken(virtualRefreshToken);
        doNothing().when(refreshTokenRepository).delete(refreshToken);
        RefreshToken updatedRefreshToken = RefreshToken.builder().
                userId(userId).
                token(virtualRefreshToken)
                .expiryDate(Instant.now().plusMillis(Duration.ofMinutes(0).toMillis()))
                .build();
        when(refreshTokenRepository.findByToken(cookie.getValue())).thenReturn(Optional.of(updatedRefreshToken));
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("AMIRA")
                .lastName("NASHER")
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(cookies);
        when(userRepository.findById(updatedRefreshToken.getUserId())).thenReturn(Optional.of(user));
        AuthenticateResponseDto authenticateResponseDto = autoWiredAuthenticationService.refreshToken(request);
        assertThat(authenticateResponseDto).isNotNull();
    }


    @Test
    @DisplayName("Testing recoverPasswordByEmail")
    public void recoverPasswordWhenEmailIsAvailable() {
        UUID userId = UUID.randomUUID();
        {
            User user = User.builder()
                    .id(userId)
                    .email("AMIRA@exmple.com")
                    .firstName("AMIRA")
                    .lastName("NASHER")
                    .deleted(false)
                    .roles(List.of(Role.USER))
                    .build();
            PasswordRecoveryDto recoveryDto = new PasswordRecoveryDto();
            recoveryDto.setEmail(user.getEmail());
            when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
            User userFound = autoWiredAuthenticationService.recoverPasswordByEmail(recoveryDto);
            assertThat(userFound).isNotNull();
        }
    }

    @Test
    @DisplayName("Testing recoverPasswordById")
    public void recoverPasswordWhenIdIsAvailable() {
        UUID userId = UUID.randomUUID();
        {
            User user = User.builder()
                    .id(userId)
                    .email("AMIRA@exmple.com")
                    .firstName("AMIRA")
                    .lastName("NASHER")
                    .password("123")
                    .deleted(false)
                    .roles(List.of(Role.USER))
                    .build();
            NewPasswordDto newPasswordDto = new NewPasswordDto();
            newPasswordDto.setPassword("321");
            when(userRepository.findById(userId)).thenReturn(Optional.of(user));
            user.setPassword(newPasswordDto.getPassword());
            when(userRepository.save(user)).thenReturn(user);
            User userFound = autoWiredAuthenticationService.recoverPasswordById(userId, newPasswordDto);
            assertEquals(userFound.getPassword(), user.getPassword());
        }
    }


    @Test
    @DisplayName("Testing recoverPasswordById when id is not available")
    public void recoverPasswordWhenIdIsNotAvailable() {
        UUID userId = UUID.randomUUID();
        {
            User user = User.builder()
                    .id(userId)
                    .email("AMIRA@exmple.com")
                    .firstName("AMIRA")
                    .lastName("NASHER")
                    .password("123")
                    .deleted(false)
                    .roles(List.of(Role.USER))
                    .build();
            NewPasswordDto newPasswordDto = new NewPasswordDto();
            newPasswordDto.setPassword("321");
            when(userRepository.findById(user.getId())).thenReturn( Optional.empty());
            Exception passwordRecoveryException = assertThrows(PasswordRecoveryException.class,()->{
                autoWiredAuthenticationService.recoverPasswordById(userId, newPasswordDto);
            });
            assertEquals("user by id " + userId + " does not exist",passwordRecoveryException.getMessage());
        }
    }

    @Test
    @DisplayName("Testing a valid token")
    public void returnTrueWhenTokenIsValid()
    {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("YULIA@gmail.com")
                .firstName("YULIA")
                .lastName("SOBOLEVA")
                .password("123")
                .deleted(false).build();
        when(userRepository.save(user)).thenReturn(user);
        var jwt = jwtService.generateToken(user);
        boolean isExist = jwtService.isTokenValid(jwt);
        assertThat(isExist).isTrue();

    }

}
