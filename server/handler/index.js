const bcrypt = require('bcrypt');
const { signJwt } = require('../utils/jwt');
const grpc = require('@grpc/grpc-js');
const jwt = require('jsonwebtoken');
let mysql = require('mysql');
let config = require('../database/index');
let connection = mysql.createConnection(config);

const RegisterHandler = async (req, res) => {
    let { name, email, password } = req.request;
    // Check if email or phone or password exist
    if (!email || !name || !password) res({ code: grpc.status.INVALID_ARGUMENT, message: 'Email/Phone/password is Required', });
    else {
        try {
            //find a user using email
            connection.query(`SELECT id from users WHERE email="${email}"`, async function (err, result) {
                if (err) res({ code: grpc.status.INTERNAL, message: 'Server Error', });
                else if (result.length) res({ code: grpc.status.ALREADY_EXISTS, message: 'Email ALready Exists', });

                if (!err && result.length === 0) {
                    // Generate Hash Password
                    password = await bcrypt.hash(password, 12);

                    // Create User into DB
                    connection.query("INSERT into users values(?,?,?,?)", [null, name, email, password], (error, response) => {
                        if (error) res({ code: grpc.status.INTERNAL, message: 'Can Not Register User', });
                        console.log(response)
                        res(null, {
                            user: {
                                id: response.insertId,
                                name,
                                email,
                            }
                        });
                    });
                }
            });
        } catch (err) {
            res({ code: grpc.status.INTERNAL, message: err.message });
        }
    }
};

const LoginHandler = async (req, res) => {
    const { email, password } = req.request;
    try {
        //find a user using email
        connection.query(`SELECT * from users WHERE email="${email}"`, async function (err, result) {
            if (err) res({ code: grpc.status.INTERNAL, message: 'Server Error', });
            if (result.length === 0) res({ code: grpc.status.NOT_FOUND, message: 'Invalid Credentials', });

            if (!err && result.length !== 0) {
                const user = { ...result[0] };

                // Check if user exist and password is correct
                if (!(await bcrypt.compare(password, user.password))) {
                    res({ code: grpc.status.INVALID_ARGUMENT, message: 'Invalid email or password', });
                }
                else {
                    // Create the Token
                    const token = signJwt(user);

                    // Send Token
                    res(null, {
                        status: 'success',
                        token,
                    });
                }
            }
        });
    } catch (err) {
        res({ code: grpc.status.INTERNAL, message: err.message });
    }
};

module.exports = {
    RegisterHandler: RegisterHandler,
    LoginHandler: LoginHandler
};

