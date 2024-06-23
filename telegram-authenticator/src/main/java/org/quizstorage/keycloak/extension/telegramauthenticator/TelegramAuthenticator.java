package org.quizstorage.keycloak.extension.telegramauthenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.Optional;

public class TelegramAuthenticator implements Authenticator {

    private static final String TELEGRAM_ATTR_NAME = "telegram_id";

    private static final String TELEGRAM_ID_REQUEST_PARAM_NAME = "telegram_id";

    private static final Logger LOG = Logger.getLogger(TelegramAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.debugf("Verifying telegram id...");
        MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
        String telegramId = decodedFormParameters.getFirst(TELEGRAM_ID_REQUEST_PARAM_NAME);
        LOG.debugf("telegram id \"%s\" confirmed", telegramId);

        Optional.ofNullable(telegramId)
                .flatMap(id -> getUserByTelegramId(context, telegramId))
                .ifPresentOrElse(
                        u -> {
                            context.setUser(u);
                            context.success();
                        },
                        context::attempted
                );
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }

    private Optional<UserModel> getUserByTelegramId(AuthenticationFlowContext context, String telegramId) {
        UserProvider users = context.getSession().users();
        return users.searchForUserByUserAttributeStream(context.getRealm(), TELEGRAM_ATTR_NAME, telegramId)
                .findFirst();
    }

}
