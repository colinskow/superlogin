'use strict';
var fs = require('fs');
var BPromise = require('bluebird');
var nodemailer = require('nodemailer');
var ejs = require('ejs');

module.exports = function(config) {

  // Initialize the transport mechanism with nodermailer
  var transporter;
  var customTransport = config.getItem('mailer.transport');
  if(config.getItem('testMode.noEmail')) {
    transporter = nodemailer.createTransport(require('nodemailer-stub-transport')());
  } else if(customTransport) {
    transporter = nodemailer.createTransport(customTransport(config.getItem('mailer.options')));
  } else {
    transporter = nodemailer.createTransport(config.getItem('mailer.options'));
  }

  this.sendEmail = function(templateName, email, locals) {
    // load the template and parse it
    var templateFile = config.getItem('emails.' + templateName + '.template');
    if(!templateFile) {
      return BPromise.reject('No template found for "' + templateName + '".');
    }
    var template = fs.readFileSync(templateFile, 'utf8');
    if(!template) {
      return BPromise.reject('Failed to locate template file: ' + templateFile);
    }
    var body = ejs.render(template, locals);
    // form the email
    var subject = config.getItem('emails.' + templateName + '.subject');
    var format = config.getItem('emails.' + templateName + '.format');
    var mailOptions = {
      from: config.getItem('mailer.fromEmail'),
      to: email,
      subject: subject
    };
    if(format==='html') {
      mailOptions.html = body;
    } else {
      mailOptions.text = body;
    }
    if(config.getItem('testMode.debugEmail')) {
      console.log(mailOptions);
    }
    // send the message
    var sendEmail = BPromise.promisify(transporter.sendMail, {context: transporter});
    return sendEmail(mailOptions);
  };

  return this;

};
