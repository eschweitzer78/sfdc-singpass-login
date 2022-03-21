global without sharing
class SingPass_RegistrationHandler
implements Auth.RegistrationHandler {
  global boolean canCreateUser(Auth.UserData data) {
    //TODO: Check whether we want to allow creation of a user with this data

    return true;
  }
  
  global User createUser(Id portalId, Auth.UserData data){
    System.debug('*** createUser ' + data);
    
    if (!canCreateUser(data)) {
        //Returning null or throwing an exception fails the SSO flow
        return null;
    }

    //if (data.attributeMap.containsKey('sfdc_networkid')) {
        //We have a community id, so create a user with community access
    
    // TODO: Get an actual account, adapt based on your needs
    // Check whether the user already exists (but has been outside of SSO)
    
      Account a = [
        SELECT Id
        FROM account
        WHERE name = 'Acme'
      ];

      Contact c = new Contact();
      c.accountId = a.Id;
      c.email = data.email;
      c.firstName = data.firstName;
      c.lastName = data.lastName;

      insert(c);

      // TODO: Customize the username and profile. Also check that the username doesn't already exist and
      // possibly ensure there are enough org licenses to create a user. Must be 80 characters or less.
      User u = new User();
      Profile p = [
        SELECT Id 
        FROM profile 
        WHERE name = 'Customer Portal User'
      ];
      u.username = data.username + '@acmecorp.com';
      u.email = data.email;
      u.lastName = data.lastName;
      u.firstName = data.firstName;
      String alias = data.username;

      // Alias must be 8 characters or less
      if (alias.length() > 8) {
          alias = alias.substring(0, 8);
      }

      u.alias = alias;
      u.languagelocalekey = UserInfo.getLocale();
      u.localesidkey = UserInfo.getLocale();
      u.emailEncodingKey = 'UTF-8';
      u.timeZoneSidKey = 'America/Los_Angeles';
      u.profileId = p.Id;
      u.contactId = c.Id;

      return u;
    /*} else {
    }*/
  }
  
  global void updateUser(Id userId, Id portalId, Auth.UserData data) {
    System.debug('*** updateUser ' + userId);
    User u = new User(id=userId);
    //TODO: Customize the username. Must be 80 characters or less.
    //u.username = data.username + '@myorg.com';
    u.email = data.email;
    u.lastName = data.lastName;
    u.firstName = data.firstName;
    update(u);
  }
}