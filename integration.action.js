/**
* Handler that will be called during the execution of a PostLogin flow.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/

const axios = require("axios");

let redirect_uri = "";
let config_obj = {};

exports.onExecutePostLogin = async (event, api) => {

  // check if IDME metadata is defined. 
  let execute_verification; 

  if(event.client.metadata.IDME_VERIFICATION!==undefined){

    let verification = event.client.metadata.IDME_VERIFICATION;
    let enforcement_policy = event.configuration.ENFORCEMENT_POLICY;
    // check if they opted in or out 
    // call it ENFORCEMENT_POLICY;
    if(enforcement_policy === 'opt_in'){
        // if it's opt in, check if IDME_VERIFICATION === 'ENABLED'
        if(verification==='enabled' || verification === 'ENABLED'){
          execute_verification = true;
        }
    }

    if(enforcement_policy === 'opt_out'){
      if(verification==='disabled' ||  verification == 'DISABLED'){
          execute_verification = false;
      }
    }
  }else{
    if(enforcement_policy === 'opt_in'){
      // if it's opt in, check if IDME_VERIFICATION === 'ENABLED'
        execute_verification = true;
    }else if(enforcement_policy === 'opt_out'){
      execute_verification = false;
    }
  }
   

  // only execute iff verification is set to true. 
  // iff opt-out == true && IDME_VERIFICATION==='disabled'
  /// iff opt-in === true &&& IDME_VERFICATION === 'enabled'
  // if there's no metadata and it's opt-in, apply everywhere
  // if it's opt-out, don't apply anywhere. 
  
  if(execute_verification === false){
    await executeIDmeVerification(event, api);
  }
};

const executeIDmeVerification = async (event, api) =>{
    let reverification_period = event.configuration.REVERIFICATION_PERIOD;

    // making sure reverification is at least once a year.
    if (reverification_period > (365 * 24)) {
      reverification_period = (365 * 24);
    }
  
    const config = await getConfigObject(event);
    config_obj = config;
  
  
    const tenant = event.tenant.id;
    // grab the state parm from the transaction for the redirect
    const { state } = event.transaction;
    redirect_uri = `https://${tenant}.${event.configuration.DOMAIN}/continue?state=${state}`;

    if(event.connection.name === 'idme-identity' || event.connection.name==='idmecommunity'){
      console.log("User coming from idme cnx; short circut action. ");
    } else{
      // check if the last_verified date is less than currentTime+customer interval;
      // let's say, for instance, we want to verify with ID.me every 30 days.
      // If 30+ days has gone by, check, reverify information.
      try {
        // get the idme_verification_timestamp off the user's app metadata
        // if and only if it exists. This is returned as a 'Dictionary Implementation'
        const { app_metadata } = event.user;
  
        let verification_needed = false;
        if (app_metadata.hasOwnProperty("idme_verification_timestamp")) {
          const verification_timestamp = app_metadata.idme_verification_timestamp;
  
          // 3600 seconds in an hour
          const offset_amount = reverification_period * (3600);
  
          // if (idme_verification_timestamp + interval) < currentTime
          const current_time = Math.round((Date.now()) / 1000);
  
          if ((verification_timestamp + offset_amount) < current_time) {
            verification_needed = true;
          }
        } else {
          // we may need one, so send them off to verify regardless?
          verification_needed = true;
        }
  
        if (verification_needed) {
          const redirect_url = await getRedirectUrl(event, config, redirect_uri);
          // send the user to ID.ME authN endpoint
          api.redirect.sendUserTo(redirect_url);
        }
      } catch (err) {
        console.error(err);
      }
    }
}

exports.onContinuePostLogin = async (event, api) => {
  // exchange the code for tokens.
  try {
    const bearer_token = await exhangeCodeForToken(event, event.request.query.code);

    console.log("event request: ");
    console.log(event.request);

    const id_me_userdata_result = await getIdMeUserData(event, bearer_token);
    console.log(id_me_userdata_result);

    if (id_me_userdata_result.status === "success") {
      api.user.setAppMetadata("idme_verification_timestamp", Math.round((Date.now()) / 1000));
      const idme_attributes = await parseResults(id_me_userdata_result.data);
      api.user.setAppMetadata("idme-attributes", idme_attributes);
    } else if (id_me_userdata_result.status === "error") {
      if (event.configuration.BLOCK_LOGIN === "true") {
        // api.access.deny("ID.me Verification Unsuccessful", "Unable to validate user attributes from Id.me");
        // redirect them back to the login page for the application
        return api.access.deny("Unable to verify ID.Me attributes");
      }
    }
  } catch (error) {
    console.error(error);
  }
};

// defining function to finish the OAuth code flow grant..

const exhangeCodeForToken = async (event, code) => {
  const redirect_url = `https://${event.tenant.id}.${event.configuration.DOMAIN}/continue?state=${event.transaction.state}`;

  // check the config object url
  let options = {
    method: "POST",
    url: "https://api.id.me/oauth/token",
    headers: {
    },
    data: `code=${code}&client_id=${event.secrets.CLIENT_ID}&client_secret=${event.secrets.CLIENT_SECRET}&redirect_uri=${redirect_url}&grant_type=authorization_code`,
  };

  if (event.configuration.VERIFICATION_TYPE === "identity" && event.configuration.DEPLOYMENT_TYPE === "sandbox") {
    options = {
      method: "POST",
      url: "https://api.idmelabs.com/oauth/token",
      headers: {
      },
      data: `code=${code}&client_id=${event.secrets.CLIENT_ID}&client_secret=${event.secrets.CLIENT_SECRET}&redirect_uri=${redirect_url}&grant_type=authorization_code`,
    };
  }

  try {
    const data = await axios.request(options);
    const bearer_token = data.data.access_token;
    return bearer_token;
  } catch (e) {
    console.log(e);
  }
};

const getIdMeUserData = async (event, token) => {
  let id_me_options = {};
  console.log("config opts");
  console.log(config_obj);
  if (event.configuration.VERIFICATION_TYPE === "identity" && event.configuration.DEPLOYMENT_TYPE === "sandbox") {
    id_me_options = {
      url: "https://api.idmelabs.com/api/public/v3/attributes",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      method: "GET",
    };
  } else {
    id_me_options = {
      url: "https://api.id.me/api/public/v3/attributes",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      method: "GET",
    };
  }
  const user_attribute_response = await axios.request(id_me_options).then((response) => ({
    status: "success",
    data: response.data,
  })).catch((err) => ({
    status: "error",
    data: err,
  }));
  return user_attribute_response;
};

// read the event.configuration object and form a configuration object
const getConfigObject = async (event) => {
  let scope_values = event.secrets.SCOPES;

  if(event.client.metadata.IDME_SCOPES!==undefined){
    scope_values = event.client.metadata.IDME_SCOPES;
  }

  const configuration_obj = {
    client_id: event.secrets.CLIENT_ID,
    verification_type: event.secrets.VERIFICATION_TYPE,
    deployment_type: event.secrets.DEPLOYMENT_TYPE,
    scopes: scope_values,
    enforcement_policy: event.secrets.ENFORCEMENT_POLICY,
    block_login: event.secrets.BLOCK_LOGIN,
    domain: event.secrets.DOMAIN
  };


  if (configuration_obj.verification_type === "community") {
    // check to see if there are multiple scopes
    const configured_scopes = event.configuration.SCOPES;
    const scope_array = configured_scopes.split(" ");

    if (scope_array.length > 2) {
      configuration_obj.root_url = "groups.id.me";
    } else {
      configuration_obj.root_url = "api.id.me";
    }
  }

  if (configuration_obj.verification_type === "identity") {
    if (configuration_obj.deployment_type === "sandbox") {
      configuration_obj.root_url = "api.idmelabs.com";
    } else if (configuration_obj.deployment_type === "production") {
      configuration_obj.root_url = "api.id.me";
    } else {
      throw new Error(`Invalid deployment type supplied. Valid options: {sandbox, production}. Supplied: ${configuration_obj.deployment_type}`);
    }
  }

  console.log(configuration_obj);
  return configuration_obj;
};

const getRedirectUrl = async (event, config_obj, redirect) => {
  // if it's multipe groups then the URL structure is a bit different
  // https://groups.id.me?client_id=[YOUR_CLIENT_ID]&redirect_uri=[YOUR_REDIRECT_URI]&response_type=code&scope=openid,military,student>

  let scope_string = config_obj.scopes;
  // check the number of scopes supplied
  const scopes_array = config_obj.scopes.split(" ");

  // if its identity verification
  let scope_uri = `scope=${scope_string}`;

  let url_prexfix = `https://${config_obj.root_url}/oauth/authorize`;

  if (config_obj.verification_type === "community") {
    if (scopes_array.length > 2) {
      scope_string = scopes_array.join();
      // change the url_prefix
      url_prexfix = `https://${config_obj.root_url}`;
      scope_uri = `scopes=${scope_string}`;
    }
  }

  const url = `${url_prexfix}?client_id=${event.secrets.CLIENT_ID}&redirect_uri=${redirect}&${scope_uri}&response_type=code`;
  console.log(`Redirect URL : ${url}`);
  return url;
};

const parseResults = async (attribute_data) => {
  // go thru the attribute data and write it to the profile app_metadata
  const idme_attributes = {};
  const { attributes } = attribute_data;
  const { status } = attribute_data;

  // attributes are an array of objects
  for (const element of attributes) {
    console.log("attribute");
    console.log(element);
    if (element.value !== null || element.value !== undefined || element.value !== "null" || element.value !== "") {
      idme_attributes[element.handle] = element.value;
    }
  }

  idme_attributes.status = status;
  console.log("id me attributes : ");
  console.log(idme_attributes);
  return idme_attributes;
};
