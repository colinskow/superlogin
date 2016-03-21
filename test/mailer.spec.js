'use strict';
var path = require('path');
var expect = require('chai').expect;

var Configure = require('../lib/configure');
var Mailer = require('../lib/mailer');

var mailerTestConfig = new Configure({
  testMode: {
    noEmail: true
  },
  mailer: {
    fromEmail: 'noreply@example.com'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../templates/email/confirm-email.ejs'),
      format: 'text'
    }
  }
});

var req = {
  protocol: 'https',
  headers: {
    host: 'example.com'
  }
};

var theUser = {
  name: 'Super',
  unverifiedEmail: {
    token: 'abc123'
  }
};

var mailer = new Mailer(mailerTestConfig);

describe('Mailer', function() {
  it('should send a confirmation email', function() {
    return mailer.sendEmail('confirmEmail', 'super@example.com', {req: req, user: theUser})
      .then(function(result) {
        var response = result.response.toString();
        expect(response.search('From: noreply@example.com')).to.be.greaterThan(-1);
        expect(response.search('To: super@example.com')).to.be.greaterThan(-1);
        expect(response.search('Subject: Please confirm your email')).to.be.greaterThan(-1);
        expect(response.search('Hi Super,')).to.be.greaterThan(-1);
        expect(response.search('https://example.com/auth/confirm-email/abc123')).to.be.greaterThan(-1);
      });
  });

});