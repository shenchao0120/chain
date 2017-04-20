package com.chain.api;

import com.chain.exception.*;
import com.chain.http.*;

import java.util.*;

import com.google.gson.annotations.SerializedName;

/**
 * An authorization grant provides provides granular access to resources exposed
 * by the Chain Core API. It maps guards (predicates that match against credentials
 * provided by clients) to policies (lists of resources).
 * <p>
 * There are two types of guards: {@link AccessTokenGuard}, which matches against
 * access tokens by ID, and {@link X509Guard}, which matches against X.509 client
 * certificates with a particular Subject field.
 * <p>
 * Currently, there are four policies exposed through the API:
 * <p><ul>
 * <li>client-readwrite: full access to the Client API, including accounts,
 *   assets, transactions, access tokens, authorization grants, etc.
 * <li>client-readonly: read-only access to the Client API. API calls that modify
 *   data in Chain Core, such as account creation, are not permitted.
 * <li>monitoring: read-only access to monitoring endpoints, such as fetching
 *   the Chain Core configuration.
 * <li>network: full access to the Network API, which allows two instances of
 *   Chain Core to connect to each other.
 * </ul>
 */
public class AuthorizationGrant {
  @SerializedName("guard_type")
  public String guardType;

  @SerializedName("guard_data")
  public Map<String, Object> guardData;

  public String policy;

  @SerializedName("created_at")
  public Date createdAt;

  /**
   * A guard that will provide access for a specific access token, identified
   * by its unique ID.
   */
  public static class AccessTokenGuard {
    public String id;

    /**
     * Specifies the ID of the token that the guard will match against.
     * @param id an access token ID (just the ID, not the full token value)
     * @return updated AccessTokenGuard object
     */
    public AccessTokenGuard setId(String id) {
      this.id = id;
      return this;
    }
  }

  /**
   * A guard that will provide access for X.509 certificates whose
   * Subject field matches a particular pattern. If a certificate's
   * Subject field contains all of the values specified in the guard,
   * the guard will produce a positive match.
   */
  public static class X509Guard {
    public String subject;

    /**
     * Specifies a Subject field in RFC2253 Distinguished Name format.
     */
    public X509Guard setSubject(String subject) {
      this.subject = subject;
      return this;
    }
  }

  /**
   * A base class for RPC builders that specify a grant, i.e. a
   * guard-policy tuple.
   * @param <T> always use the child class that extends BaseBuilder
   */
  public static class BaseBuilder<T> {
    @SerializedName("guard_type")
    private String guardType;

    @SerializedName("guard_data")
    private Map<String, Object> guardData;

    private String policy;

    /**
     * Specifies a guard that will match against a specific access token.
     * @param g a guard that matches against an access token
     * @return updated builder object
     */
    public T setGuard(AccessTokenGuard g) {
      this.guardType = "access_token";
      this.guardData = new HashMap<>();
      guardData.put("id", g.id);
      return (T) this;
    }

    /**
     * Specifies a guard that will match against X.509 certificates.
     * @param g a guard that matches against X.509 certificates
     * @return updated builder object
     */
    public T setGuard(X509Guard g) {
      guardType = "x509";
      this.guardData = new HashMap<>();
      guardData.put("subject", g.subject);
      return (T) this;
    }

    /**
     * Sets the policy to grant to credentials that match the guard.
     * @param policy One of "client-readwrite", "client-readonly", "monitoring", or "network"
     * @return updated builder object
     */
    public T setPolicy(String policy) {
      this.policy = policy;
      return (T) this;
    }
  }

  /**
   * Sets up a grant creation API call.
   */
  public static class Builder extends BaseBuilder<Builder> {
    /**
     * Creates a new grant with the parameters in this Builder instance.
     * @param client the client object providing connectivity to the Chain Core instance
     * @throws ChainException
     */
    public void create(Client client) throws ChainException {
      client.request("create-authorization-grant", this, SuccessMessage.class);
    }
  }

  /**
   * Sets up a grant deletion API call.
   */
  public static class DeletionBuilder extends BaseBuilder<DeletionBuilder> {
    /**
     * Deletes a new grant with the parameters in this Builder instance.
     * @param client the client object providing connectivity to the Chain Core instance
     * @throws ChainException
     */
    public void delete(Client client) throws ChainException {
      client.request("delete-authorization-grant", this, SuccessMessage.class);
    }
  }

  /**
   * Retrieves a list of all authorization grants in Chain Core.
   * @param client the client object providing connectivity to the Chain Core instance
   * @return a list of authorization grants
   * @throws ChainException
   */
  public static List<AuthorizationGrant> listAll(Client client) throws ChainException {
    ListResponse resp = client.request("list-authorization-grants", null, ListResponse.class);
    return resp.items;
  }

  private class ListResponse {
    public java.util.List<AuthorizationGrant> items;
  }
}
