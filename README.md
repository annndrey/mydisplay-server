**mydisplay-server API**

---

## Users (DB clients)


1. URL: /api/users /api/users/[userid]
---

## Contacts
1. /api/contacts /api/contacts/[contactid]
2. contact activities /api/contacts/<int:contactid>/activities /api/contacts/<int:contactid>/activities/<int:activityid>
3. contact notes /api/contacts/<int:contactid>/notes /api/contacts/<int:contactid>/notes/<int:noteid>

---

## Properties

1. /api/properties /api/properties/<int:propertyid>
2. property appraisals /api/properties/<int:propertyid>/appraisals /api/properties/<int:propertyid>/appraisals/<int:appraisalid>
3. property contacts /api/properties/<int:propertyid>/contacts /api/properties/<int:propertyid>/contacts/<int:contactid>

## Notes

1. Appraisal notes /api/appraisals/<int:appraisalid>/notes /api/appraisals/<int:appraisalid>/notes/<int:noteid>
2. activity notes /api/activities/<int:activityid>/notes /api/activities/<int:activityid>/notes/<int:noteid>
3. contact notes /api/contacts/<int:contactid>/notes /api/contacts/<int:contactid>/notes/<int:noteid>

## To run the app in the docker container:
1. docker build -t realestate:latest .
2. docker run -p 3306:3306 --name mysql -d -e MYSQL_RANDOM_ROOT_PASSWORD=yes -e MYSQL_DATABASE=realestate -e MYSQL_USER=realestate  -e MYSQL_PASSWORD=DbUserPassword mysql/mysql-server:5.7 
3. docker run -it --name realestate -d -p 8000:5000 --link mysql:dbserver realestate:latest
4. Now the app is available on 8000 port of the host machine
