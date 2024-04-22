#!/bin/bash
echo "Please provide user emails to delete from IAM in comma separated strings without spaces, like:alex.murfy@albanero.io,brian.show@albanero.io"

read emails

echo "Provided user emails are $emails"

echo "Please provide mongodb connection URL"

read mongoString

echo "Provided database connection URL is $mongoString"

echo "Press any key to proceed."
read

# Convert emails array to JSON representation
emails_json="\"${emails[@]}\""

# MongoDB Connection
mongo "$mongoString" <<EOF
print("Current database is " + db);
let emails = $emails_json.split(",");
emails.forEach(function(user) {
  // Perform actions for each item
  print("Start-------------->Searching userProfile related to: " + user+"<-------------Start");
  try {
    let userProfile = db.userProfile.findOne({ emailId: user });
    if (userProfile) {
      print("userId of " + user + " is : " + userProfile._id);

      print("->Deleting user : "+user+" from userProfile");
      db.userProfile.remove({ _id: userProfile._id })
      print("->Successfully deleted user : "+user+" from userProfile collection");

      const userId = userProfile._id.str;

      print("->Deleting user : "+user+" from userAuthHistory collection");
      db.userAuthHistory.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from userAuthHistory collection");

      print("->Deleting user : "+user+" from mfaStatus collection");
      db.mfaStatus.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from mfaStatus collection");

      print("->Deleting user : "+user+" from userOrgRole collection");
      db.userOrgRole.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from userOrgRole collection");

      print("->Deleting user : "+user+" from userSession collection");
      db.userSession.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from userSession collection");

      print("->Deleting user : "+user+" from accountStatus collection");
      db.accountStatus.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from accountStatus collection");

      print("->Deleting user : "+user+" from changeSecSettings collection");
      db.changeSecSettings.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from changeSecSettings collection");

      print("->Deleting user : "+user+" from secQuesStatus collection");
      db.secQuesStatus.remove({ userId : userId });
      print("->Successfully deleted user : "+user+" from secQuesStatus collection");
      print("End-------------Successfully deleted user : "+user+" from all collection<-----------------End");
      
    } else {
      print("End-------------->No user found with this emailId: " + user+"<-----------------End");
      return;
    }
  } catch (error) {
    print("->Error occurred while retrieving user: " + user+"<-");
    print("End-------------->Error message: " + error.message+"<--------------------End");
  }
});
EOF


