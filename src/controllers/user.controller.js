import asyncHandler from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"


const generateAccessAndRefreshTokens = async(userId) =>{
   try {
      const user = await User.findById(userId)
      const accessToken = user.generateAccessToken()
      const refreshToken = user.generateRefreshToken()
      
      user.refreshToken = refreshToken
      await user.save({ validateBeforeSave: false })

      return {accessToken, refreshToken}

   } catch (error) {
      throw new ApiError(500, "Something went wrong while generating referesh and access token")
   }
}

const registerUser = asyncHandler( async (req, res) => {
   // get user details from frontend
   // validation - not empty
   // checl if user is already exists : email or username
   // check for images,check for avatar
   // upload them to cloudinary
   // create user object - create entry in db
   // remove password and refresh token field from response
   // check for user creation
   // return res
    
   const {fullName, email, username, password} = await req.body
   console.log("email: ", email)
   console.log("fullName: ", fullName)
   console.log("password: ", password)

   if(
    [fullName, email, username, password].some((field) => field?.trim() === "")
   ){
    throw new ApiError(400, "All fields are required")
   }
   
   const existedUser = await User.findOne({
     $or: [{ username }, { email }]
   })

   if(existedUser){
      throw new ApiError(409, "User with email or username already exists")
   }
   console.log(req.files);
   
   /** const avatarLocalPath = req.files?.avatar[0]?.path;
   const coverImageLocalPath = req.files?.coverImage[0]?.path; this code is not working as it was supposed to work**/

   let coverImageLocalPath;
   let avatarLocalPath;

   if (req.files) {
      if (Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
          coverImageLocalPath = req.files.coverImage[0].path;
      }
      if (Array.isArray(req.files.avatar) && req.files.avatar.length > 0) {
          avatarLocalPath = req.files.avatar[0].path;
      }
  }


   if(!avatarLocalPath){
      throw new ApiError(400, "Avatar file is required")
   }
   
   const avatar = await uploadOnCloudinary(avatarLocalPath)
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)
   
   if(!avatar){
       throw new ApiError(400, "Avatar file is required")
   }

   const user = await User.create({
      fullName,
      avatar: avatar.url,
      coverImage: coverImage?.url || "",
      email,
      password,
      username: username.toLowerCase()
   })

   const createdUser = await User.findById(user._id).select( "-password -refreshToken")

   if(!createdUser){
       throw new ApiError(500, "Something went wrong while registering the user")
   }

   return res.status(201).json(
      new ApiResponse(200, createdUser, "User registered successfully")
   )

})

const loginUser = asyncHandler(async (req, res) => {
   // req body -> data 
   // find user using username or email
   // password check
   // access and refresh token
   // send cookie 

   const {email, username, password} = req.body
   console.log(email);

   if(!(username || email)){
      throw new ApiError(400, "username or email is required")
   }

   const user = await User.findOne({
      $or: [{username},{email}]
   })

   if(!user) {
      throw new ApiError(404, "User does not exist")
   }
   
   const isPasswordValid = await user.isPasswordCorrect(password)

   if(!isPasswordValid) {
      throw new ApiError(401, "Invalid user credentials")
   }

   const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

   const options = {
      httpOnly: true,
      secure: true
   }

   return res
   .status(200)
   .cookie("accessToken", accessToken, options)
   .cookie("refreshToken", refreshToken, options)
   .json(
      new ApiResponse(
         200,
         {user: loggedInUser, accessToken, refreshToken},
         "User logged In Successfully"
      )
   )

})

const logoutUser = asyncHandler( async(req, res) => {
    await User.findByIdAndUpdate(
      req.user._id, //got this user from auth middleware
      {
         $unset: {
            refreshToken: 1 //this remove the field from the document
         }
      },
      {
         new: true
      }
    )

    const options = {
      httpOnly: true,
      secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))

} )

const refreshAccessToken = asyncHandler( async(req, res) => {
   const incomingRefreshToken = req.cookies.refreshToken

   if(!incomingRefreshToken){
      throw new ApiError(401,"Unauthorised request")
   }
   
   try {
      const decodedToken = jwt.verify(
         incomingRefreshToken, 
         process.env.REFRESH_TOKEN_SECRET
      )
   
      const user = await User.findById(decodedToken?._id)
   
      if(!user){
         throw new ApiError(401, "Invalid refresh token")
      }
   
      if(!incomingRefreshToken !== user?.refreshToken){
         throw new ApiError(401, "Refresh token is expired or used")
      }
   
      const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
   
      const options = {
         httpOnly: true,
         secure: true
      }
   
      return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
         new ApiResponse(
            200,
            {accessToken, refreshToken: newRefreshToken},
            "Access token refreshed"
         )
      )
   } catch (error) {
      throw new ApiError(401, error?.message || "Invalid refresh token")
   }

} )

const changeCurrentPassword = asyncHandler( async(req,res) => {
   const {oldPassword, newPassword} = req.body
   const user = await User.findById(req.user?._id)
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

   if(!isPasswordCorrect){
      throw new ApiError(401, "Invalid password")
   }
   user.password = newPassword
   await user.save({validateBeforeSave: false})

   return res
   .status(200)
   .json(new ApiResponse(200, {}, "Passoword changed successfully"))
} )

const getCurrentUser = asyncHandler( async(req, res) => {
   return res
   .status(200)
   .json(200, req.user, "current user fetched successfully")
} )

export {
   registerUser, 
   loginUser, 
   logoutUser, 
   refreshAccessToken,
   getCurrentUser,
   changeCurrentPassword
}