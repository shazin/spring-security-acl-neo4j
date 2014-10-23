spring-security-acl-neo4j
=========================

Supporting Library for Spring Security Acl with Neo4j Graph Database

Motivation
----------

The motivation behind this project was to increase performance in Spring Security ACL, by eliminating the Bottleneck created by using traditional RDBMS as backend data store. Read this <a href="http://shazsterblog.blogspot.com/2014/10/neo4j-graph-database-backend-for-spring_22.html">post</a> for more information.

Design
------

acl_sid, acl_class, acl_object_identity and acl_entry are modelled represpectively using nodes SidNode, ClassNode, AclNode and AceNode in the following Graph.

![alt tag](https://raw.github.com/shazin/spring-security-acl-neo4j/master/Graph.png)

Testing
-------

Testing against H2 Database and Inmemory Neo4j Test Database with dataset 200 ACL Entries (2 for each Object Identity), 3 Sids (Including logged in User Sid), 100 Classes and 100 Object Identities. 

Testing was mainly focused on Retrieval and to retrieve 50 non following Object Identities with ACL Entries (2 for each Object Identity) while running four random times with an Empty Cache, following were the results.

![alt tag](https://raw.github.com/shazin/spring-security-acl-neo4j/master/Chart.jpg)

Feedback
--------

Any feedback positive or negative as long as they are constructive can be sent to <a href="mailto:shazin.sadakath@gmail.com">Shazin</a>
