import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"


/**We are creating this middleware to achieve logout functionality: The problem: To logout the user we first need to know which user is currently logged in and we don't have any method to do that. So here what this middleware will do :
 * 1.) fetch the token from the cookies
 * 2.) verify the token with jwt, after verification jwt provides us decoded information i.e. everything we provided during the generateAcessToken method.
 * 3.) We will take the ._id from the decoded info and then search the user from databse with the id.
 * 4.) After getting the user we will add that user to the req.
 * In this way the logout method will have the access of user. **/ 

export const verifyJWT = asyncHandler( async(req, res, next) => {
    try {
        const token = req.cookies?.accessToken
    
        if(!token){
            throw new ApiError(401, "Unauthorised request")
        }
    
        const decodedTokenInfo = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        
        const user = await User.findById(decodedTokenInfo?._id).select("-password -refreshToken")
    
        if(!user){
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user;
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token")
    }

} )