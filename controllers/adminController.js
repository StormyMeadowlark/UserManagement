const User = require("../models/User");
// Assuming you have models for Posts, Comments, Likes, etc., you'll need to import them here.
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger"); // Logging utility

exports.getDashboardData = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction("Fetching Dashboard Data", `Tenant ID: ${tenantId}`);

    // 1. Get the total number of users for this tenant
    const usersCount = await User.countDocuments({ tenant: tenantId });

    // 2. Get the total number of posts for this tenant (if you have a Post model)
    // const postsCount = await Post.countDocuments({ tenant: tenantId });

    // 3. Get the number of new users registered in the last 7 days for this tenant
    const newUsersCount = await User.countDocuments({
      tenant: tenantId,
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    });

    // 4. Get the number of posts created in the last 7 days for this tenant
    // const newPostsCount = await Post.countDocuments({
    //   tenant: tenantId,
    //   createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    // });

    // 5. Get the number of comments made in the last 7 days for this tenant
    // const newCommentsCount = await Comment.countDocuments({
    //   tenant: tenantId,
    //   createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    // });

    // 6. Get the number of likes on posts in the last 7 days for this tenant
    // const newLikesCount = await Like.countDocuments({
    //   tenant: tenantId,
    //   createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    // });

    // 7. Get the 10 most recent users for this tenant
    const recentUsers = await User.find({ tenant: tenantId })
      .sort({ createdAt: -1 })
      .limit(10)
      .select("username email createdAt");

    // 8. Get the 10 most recent posts for this tenant (if you have a Post model)
    // const recentPosts = await Post.find({ tenant: tenantId })
    //   .sort({ createdAt: -1 })
    //   .limit(10)
    //   .select("title createdAt");

    // Prepare the final dashboard data
    const dashboardData = {
      usersCount,
      newUsersCount,
      recentUsers, // Add other fields like postsCount, newPostsCount, etc., as needed
    };

    logAction("Dashboard Data Fetched", `Tenant ID: ${tenantId}`);

    res.status(200).json({
      status: "success",
      data: dashboardData,
    });
  } catch (error) {
    logAction(
      "Error Fetching Dashboard Data",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error fetching dashboard data" });
  }
};
