var mongoose = require("mongoose");
var bcrypt = require("bcrypt-nodejs");

var userSchema = mongoose.Schema({
  local: {
    name: String,
    email: String,
    password: String,
    publickey: [
      {
        type: String
      }
    ],
    handle: [
      {
        type: String
      }
    ]
  },
    car:{
    name: String,
    heating:
        {
            left: String,
            right:String
        },
   ventilation:
        {
            left: String,
            right:String
        }
    },
    map: {
      location: [
          {
              type: String

          }
        ],
       density:
           [
               {
                   type:String
               }
           ]
    },

  facebook: {
    id: String,
    token: String,
    email: String,
    name: String,
    username: String,
      location: String,
      birthday: String,
      hometown: String,
      likes: [
          {
              type: String
          }
      ],
      taggedlat:[
          {
              type: String
          }
      ],
      taggedlong:[
          {
              type: String
          }
      ]
  },
  twitter: {
    id: String,
    token: String,
    displayName: String,
    username: String
  },
  google: {
    id: String,
    token: String,
    email: String,
    name: String
  }
});

userSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

userSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model("User", userSchema);
