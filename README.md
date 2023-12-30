# c-chat
simple chat client and server with C

# comunicates
comunication protocol in this chat works on comunicates which tell server how to manage incoming data
- GET_ALL_MESSAGES\nUSERNAME\n
 - server will answer with all messages this username is recipent or sender
- GET_NEW_MESSAGES\nUSERNAME\n
 - server will answer with all messages this username is recipent to and message status is 0 (unread)
 - clients are asking for an update every 1s
- SEND_MESSAGE\nSENDER\nRECIEVER\nCONTENT\n
 - server will save all messages to db and reply with "message sent!"
- SET_MESSAGE_STATUS\nMESSAGE_ID
 - server will make sql query to update chosen msg status from 0 to 1
- CHECK_USER_STATUS\nUSERNAME\n
 - server will reply with json file where status 0 means offline and 1 means online