create table "USERS"(
    ID int not null AUTO_INCREMENT,
    EMAIL varchar(100) not null unique,
    PWD varchar(200) not null,
    ROLE VARCHAR(20),
    PRIMARY KEY ( ID )
);

create table TOPIC(
    ID int not null AUTO_INCREMENT,
    USER_ID int,
    NAME varchar(1000) not null unique,
    SCOPE VARCHAR(15) not null,
    PRIMARY KEY ( ID ),
    foreign key (USER_ID) references USERS(ID)
);

create table OPINION(
    ID int not null AUTO_INCREMENT,
    USER_ID int,
    TOPIC_ID int,
    DETAILS varchar(2000) not null,
    PRIMARY KEY ( ID ),
    foreign key (USER_ID) references USERS(ID),
    foreign key (TOPIC_ID) references TOPIC(ID)
);

create table AUTHORITY(
    ID int not null AUTO_INCREMENT,
    USER_ID int,
    NAME varchar(40) not null,
    PRIMARY KEY ( ID ),
    foreign key (USER_ID) references USERS(ID)
);

