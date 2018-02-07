import fs from "fs";
import BPromise from "bluebird";
import nodemailer from "nodemailer";
import ejs from "ejs";

export default class {
  constructor(config) {
    // Initialize the transport mechanism with nodermailer
    this.config = config;
    const customTransport = config.getItem("mailer.transport");
    if (config.getItem("testMode.noEmail")) {
      this.transporter = nodemailer.createTransport(require("nodemailer-stub-transport")());
    }
    else if (customTransport) {
      this.transporter = nodemailer.createTransport(customTransport(config.getItem("mailer.options")));
    }
    else {
      let options = config.getItem("mailer.options");
      if (!options) {
        // disable e-mail support if not configured
        this.disableMail = true;
        return;
      }
      this.transporter = nodemailer.createTransport(config.getItem("mailer.options"));
    }
  }

  sendEmail(templateName, email, locals) {
    if (this.disableMail) {
      // we don't send emails
      // return immediately
      return;
    }
    // load the template and parse it
    var templateFile = this.config.getItem("emails." + templateName + ".template");
    if (!templateFile) {
      return BPromise.reject("No template found for \"" + templateName + "\".");
    }
    var template = fs.readFileSync(templateFile, "utf8");
    if (!template) {
      return BPromise.reject("Failed to locate template file: " + templateFile);
    }
    var body = ejs.render(template, locals);
    // form the email
    var subject = this.config.getItem("emails." + templateName + ".subject");
    var format = this.config.getItem("emails." + templateName + ".format");
    var mailOptions = {
      from: this.config.getItem("mailer.fromEmail"),
      to: email,
      subject: subject
    };
    if (format === "html") {
      mailOptions.html = body;
    }
    else {
      mailOptions.text = body;
    }
    if (this.config.getItem("testMode.debugEmail")) {
      console.log(mailOptions);
    }
    // send the message
    var sendEmail = BPromise.promisify(this.transporter.sendMail, {context: this.transporter});
    return sendEmail(mailOptions);
  };
};
