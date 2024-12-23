package socialMedia;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;
import socialMedia.config.SecurityConfiguration;
import socialMedia.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import socialMedia.model.Role;
import socialMedia.model.User;
import socialMedia.repository.UserRepository;
import socialMedia.service.*;
import java.util.*;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@Import(SecurityConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@AutoConfigureMockMvc
@Transactional
class McAuthEndpointsTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:12.3"));

    @Test
    void connectionEstablished() {
        assertThat(postgres.isCreated()).isTrue();
        assertThat(postgres.isRunning()).isTrue();
    }

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CaptchaService captchaService;


    @MockBean
    private UserRepository userRepository;

    @MockBean
    private AuthenticationService authenticationService;



    @BeforeEach
    void setUp() {
        postgres.withReuse(true);
        postgres.start();
    }


    @Test
    @DisplayName("Testing register endpoint")
    void registerUserTest() throws Exception {
        AuthenticationService authenticationService = mock(AuthenticationService.class);
        RegistrationDto registrationDto = new RegistrationDto();
        registrationDto.setEmail("AMIRA@exmple.com");
        registrationDto.setFirstName("John");
        registrationDto.setLastName("Doe");
        registrationDto.setPassword1("123");
        registrationDto.setPassword2("123");
        String captcha = captchaService.generateCaptcha();
        captchaService.validateCaptcha(captcha);
        registrationDto.setCaptchaSecret(captcha);
        doNothing().when(authenticationService).register(registrationDto);
        mockMvc.perform(post("/api/v1/auth/register")
                        .content(asJsonString(registrationDto))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print());
        assertThat(captchaService.generateCaptcha()).isNotEmpty();

    }


    @Test
    @DisplayName("Testing login endpoint")
    void loginTest() throws Exception {
        AuthenticateDto authenticateDto = new AuthenticateDto();
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("EMILY")
                .firstName("EDWARD")
                .password(passwordEncoder.encode("123"))
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        when(userRepository.findByEmail("AMIRA@exmple.com")).thenReturn(Optional.of(user));
        authenticateDto.setEmail("AMIRA@exmple.com");
        authenticateDto.setPassword("123");
        AuthenticateResponseDto authenticateResponseDto = new AuthenticateResponseDto();
        authenticateResponseDto.setAccessToken("eyJhbGciOiJIUzI1NiJ9.eyJyb2xlcyI6WyJVU0VSIl0sImlkIjoiZDc2MWU3YWItMGFiNy00MTM5LTk0ZjktOWJhYzUxZDY0MWFmIiwiZW1haWwiOiJHT09GWUBnbWFpbC5jb20iLCJzdWIiOiJHT09GWUBnbWFpbC5jb20iLCJpYXQiOjE3MjUwMTU5NjMsImV4cCI6MTcyNTE1OTk2M30.Hp0XgHrVTmHBLO9r42uMyHCQ-5mMPfEBvjyHejVpoGQ");
        authenticateResponseDto.setRefreshToken("bcf748c3-3556-4080-9fe7-79f6c62031b6");
        when(authenticationService.login(any(AuthenticateDto.class),any(HttpServletResponse.class))).thenReturn(authenticateResponseDto);
        mockMvc.perform(post("/api/v1/auth/login")
                        .content(asJsonString(authenticateDto))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").value(authenticateResponseDto.getAccessToken()))
                .andExpect(jsonPath("$.refreshToken").value(authenticateResponseDto.getRefreshToken()))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    @DisplayName("Testing checkTokenValidity endpoint")
    void checkTokenValidityIfValidTest() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjpbIlVTRVIiXSwiaWQiOiJkNzYxZTdhYi0wY";
        when(jwtService.isTokenValid(token)).thenReturn(true);
        mockMvc.perform(get("/api/v1/auth/check-validation")
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().string("true"))
                .andDo(print());
    }

    @Test
    @DisplayName("Testing checkTokenValidity for invalid token endpoint")
    void checkTokenValidityIfInValidTest() throws Exception {
        String token = "53A73E5F1D635A75327855";
        when(jwtService.isTokenValid(token)).thenReturn(false);
        mockMvc.perform(get("/api/v1/auth/check-validation")
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().string("false"))
                .andDo(print());
        verify(jwtService).isTokenValid(token);
    }


    @Test
    @DisplayName("Testing refreshToken endpoint")
    void refreshTokenTest() throws Exception {
        String previousRefreshToken = "3734404a-a43d-4056-8f9d-c8bc27441e9f";
        String accessToken = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlcyI6WyJVU0VSIl0sImlkIjoiZDc2MWU3YWItMGFiNy00MTM5LTk0ZjktOWJhYzUxZDY0MWFmIiwiZW1haWwiOiJHT09GWUBnbWFpbC5jb20iLCJzdWIiOiJHT09GWUBnbWFpbC5jb20iLCJpYXQiOjE3MjUwMTU5NjMsImV4cCI6MTcyNTE1OTk2M30.Hp0XgHrVTmHBLO9r42uMyHCQ-5mMPfEBvjyHejVpoGQ";
        AuthenticateResponseDto authenticateResponseDto = new AuthenticateResponseDto();
        authenticateResponseDto.setAccessToken(accessToken);
        authenticateResponseDto.setRefreshToken(previousRefreshToken);
        when(authenticationService.refreshToken(any(HttpServletRequest.class))).thenReturn(authenticateResponseDto);
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(status().isOk())
                .andDo(print());
    }


    @Test
    @DisplayName("Testing passwordRecoveryById endpoint")
    void passwordRecoveryByIdTest() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("EMILY")
                .firstName("EDWARD")
                .password(passwordEncoder.encode("123"))
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        NewPasswordDto newPasswordDto = new NewPasswordDto();
        newPasswordDto.setPassword("321");
        when(authenticationService.recoverPasswordById(userId, newPasswordDto)).thenReturn(user);
        user.setPassword(passwordEncoder.encode(newPasswordDto.getPassword()));
        mockMvc.perform(post("/api/v1/auth/password/recovery/{linkId}", userId)
                .content(asJsonString(newPasswordDto))
                .contentType(MediaType.APPLICATION_JSON));
    }


    @Test
    @DisplayName("Testing passwordRecovery endpoint")
    void passwordRecoveryTest() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("AMIRA@exmple.com")
                .firstName("VECTOR")
                .firstName("VITALIVICH")
                .password(passwordEncoder.encode("123"))
                .deleted(false)
                .roles(List.of(Role.USER))
                .build();
        PasswordRecoveryDto passwordRecoveryDto = new PasswordRecoveryDto();
        passwordRecoveryDto.setEmail(user.getEmail());
        when(authenticationService.recoverPasswordByEmail(passwordRecoveryDto)).thenReturn(user);
        mockMvc.perform(post("/api/v1/auth/password/recovery", userId)
                        .content(asJsonString(passwordRecoveryDto))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.email").value(user.getEmail()))
                .andExpect(jsonPath("$.password").value(user.getPassword()))
                .andExpect(jsonPath("$.firstName").value(user.getFirstName()))
                .andExpect(jsonPath("$.lastName").value(user.getLastName()))
                .andDo(print());
    }

    @Test
    void captchaActionsHandlerTest() throws Exception {
        String captcha = captchaService.generateCaptcha();
        String uri = "http://79.174.80.200:9095/api/v1/auth/captcha/displayImage";
        mockMvc.perform(get("/api/v1/auth/captcha")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.image").value(uri));
        captchaService.createImage(captcha);
        mockMvc.perform(get("/api/v1/auth/captcha/displayImage")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse();
    }

    public static String asJsonString(final Object obj) {
        {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.registerModule(new JavaTimeModule());
                return objectMapper.writeValueAsString(obj);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}