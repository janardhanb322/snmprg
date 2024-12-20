import smtplib
from email.message import EmailMessage
def sendmail(to,subject,body):
    server=smtplib.SMTP_SSL('smtp.gmail.com',465)
    server.login('pallavisabbisetty@gmail.com','rqem yqri uvrc eoyb')
    msg=EmailMessage()
    msg['FROM']='pallavisabbisetty@gmail.com'
    msg['To']=to
    msg['SUBJECT']=subject
    msg.set_content(body)
    server.send_message(msg)
    server.close()