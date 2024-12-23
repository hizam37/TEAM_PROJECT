package socialMedia.service;

import socialMedia.model.RefreshToken;
import socialMedia.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${token.signing.refreshTokenExpiration}")
    private Duration refreshTokenExpiration;
    public RefreshToken generateRefreshTokenByUserId(UUID userId)
    {
        var refreshToken = RefreshToken.builder().token(UUID.randomUUID().toString())
                .userId(userId)
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration.toMillis()))
                .build();
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }


    public Optional<RefreshToken> findByRefreshToken(String token)
    {
        return refreshTokenRepository.findByToken(token);
    }


    public RefreshToken checkAndUpdateRefreshToken(RefreshToken token)
    {
        if(token.getExpiryDate().compareTo(Instant.now())<0)
        {
            refreshTokenRepository.delete(token);
            var refreshToken = RefreshToken.builder().token(token.getToken())
                    .userId(token.getUserId())
                    .expiryDate(Instant.now().plusMillis(refreshTokenExpiration.toMillis()))
                    .build();
            refreshTokenRepository.save(refreshToken);
            return refreshToken;

        }

        return token;
    }






}
