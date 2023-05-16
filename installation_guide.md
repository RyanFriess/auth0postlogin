ID.me provides secure identity proofing, authentication, and community affiliation verification for government and businesses across sectors.
The ID.me Auth0 post-login integration is for both identity proofing and community verification. This can be configured within your existing Auth0 flows to trigger verification appropriate to your use cases.

## Prerequisites
1. Before you begin, sign up for an ID.me Developer Account. [Sign up for free](https://developers.id.me/).
2. Reach out to the ID.me Sales Engineer team: [partnersupport@id.me](partnersupport@id.me)

## Set Up Your ID.me Developer account:
1. Proceed to Start a New Integration and click Continue
2. Input organization information and click Continue
3. Once an organization is created, you can proceed to View My Applications
4. Click Create New
5. Input application information. Please note, Only application name, display name, and redirect URI are required fields
6. nter your Auth0 Redirect URI following the format: https://YOUR_DOMAIN/login/callback
7. Once all fields are input and formatted correctly, you may proceed to create your ID.me application by clicking Continue

## Add the ID.me Auth0 Action
**Note:** Once the Action is successfully deployed, all logins for your tenant will be processed by this integration. Before activating the integration in production, [install and verify this Action on a test tenant](https://auth0.com/docs/get-started/auth0-overview/create-tenants/set-up-multiple-environments).
1. Select **Add Integration** (at the top of this page).
2. Read the necessary access requirements, and select **Continue**.
3. Configure the integration using the following fields:
   * **Community or Identity** Select whether you will be leveraging ID.me's Community or Identity Verification solution.
   * **Sandbox or Production** Select whether you will be leveraging ID.me's Production (api.id.me) or Sandbox (api.idmelabs.com) endpoints
   * **Timestamp** Specifies, in hours, how often you would like to prompt your users for ID.me Verification.
   * **Client ID**  Unique Identifier that specifies your specific verification workflow and user experience. Capture this from the ID.me Developer Portal.
   * **Client Secret** Authenticates your specific verification workflow and user experience. Capture this from the ID.me Developer Portal.
   * **Scopes** Enter the desired ID.me scope(s).
1. Add the integration to your Library by selecting **Create**.
2. In the modal that appears, select the **Add to flow** link.
3. Drag the Action into the desired location in the flow.
4. Select **Apply Changes**.

## ID.me Pre-Verified Network
Once users verify their identity with ID.me with any of our partners in our network, they will not be be prompted to verify again unless their credentials expire. These users will still have to accept the permissions to share their user attributes your app has requested. To enforce identity verification, please reach out to [partnersupport@id.me](partnersupport@id.me)

## Results
Once the integration has been configured, your users will be redirected to sign into ID.me where they will be prompted for Identity or Community Verification. Post-successful verification, the ID.me user attributes will be stored under the app_metadata section of the Auth0 account.

## Troubleshooting
Email ID.me at [partnersupport@id.me](partnersupport@id.me) for any issues with your ID.me's Auth0 integration.