package org.wso2.carbon.identity.revoke.endpoint;

import com.google.gson.Gson;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

@Path("/revokeByAdmin")
public class RevokeEndpoint {

    private static final Log log = LogFactory.getLog(RevokeEndpoint.class);

    @POST
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response revoke(@Context HttpServletRequest request,
                           MultivaluedMap<String, String> paramMap) {

        List<String> usernames = paramMap.get("username");
        List<String> userstoreDomains = paramMap.get("userstoredomain");
        List<String> clientIDs = paramMap.get("clientID");

        if (CollectionUtils.isEmpty(usernames)) {
            return getResponse(Response.Status.BAD_REQUEST, "Cannot find valid username in the request");
        }

        String username = usernames.get(0);

        if (CollectionUtils.isNotEmpty(userstoreDomains)) {
            username = UserCoreUtil.addDomainToName(username, userstoreDomains.get(0));
        }

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

        username = UserCoreUtil.addTenantDomainToEntry(username, CarbonContext.getThreadLocalCarbonContext().
                getTenantDomain());

        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        try {
            OAuthConsumerAppDTO[] oAuthConsumerDAO = oAuthAdminService.getAppsAuthorizedByUser();
            if (oAuthConsumerDAO.length < 1) {
                return getResponse(Response.Status.ACCEPTED, "Cannot find authorized Apps to revoke access tokens for " +
                        "user: " + username);
            }
            for (OAuthConsumerAppDTO oAuthConsumerAppDTO : oAuthConsumerDAO) {
                if (CollectionUtils.isNotEmpty(clientIDs)) {
                    if (clientIDs.get(0).equals(oAuthConsumerAppDTO.getOauthConsumerKey())) {
                        revokeTokensOfUserForAuthzApp(username, oAuthAdminService, oAuthConsumerAppDTO);
                        break;
                    }
                } else {
                    revokeTokensOfUserForAuthzApp(username, oAuthAdminService, oAuthConsumerAppDTO);
                }

            }
        } catch (IdentityOAuthAdminException e) {
            log.error(e);
            return getResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Error Occurred while revoking access tokens for user: " + username);
        }
        return getResponse(Response.Status.OK, "Successfully Revoked Access Tokens for user: " + username);
    }

    private void revokeTokensOfUserForAuthzApp(String username, OAuthAdminService oAuthAdminService,
                                               OAuthConsumerAppDTO oAuthConsumerAppDTO) throws
    IdentityOAuthAdminException {
        OAuthRevocationRequestDTO oAuthRevocationRequestDTO = new OAuthRevocationRequestDTO();
        oAuthRevocationRequestDTO.setApps(new String[]{oAuthConsumerAppDTO.getApplicationName()});
        oAuthRevocationRequestDTO.setAuthzUser(username);
        oAuthRevocationRequestDTO.setConsumerKey(oAuthConsumerAppDTO.getOauthConsumerKey());
        oAuthRevocationRequestDTO.setConsumerSecret(oAuthConsumerAppDTO.getOauthConsumerSecret());
        if (log.isDebugEnabled()) {
            log.debug("Revoking access tokens for Client ID: " + oAuthConsumerAppDTO.getOauthConsumerKey() +
                    " & user: " + username);
        }
        oAuthAdminService.revokeAuthzForAppsByResoureOwner(oAuthRevocationRequestDTO);
    }

    private Response getResponse(Response.Status status, String msg) {
        StatusMsg statusMsg = new StatusMsg();
        statusMsg.setMsg(msg);
        Gson gson = new Gson();
        String responseBody = gson.toJson(statusMsg);
        return Response.status(status).entity(responseBody).build();
    }
}
