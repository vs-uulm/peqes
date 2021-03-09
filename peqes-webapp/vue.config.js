module.exports = {
  "publicPath": "/",
  "devServer": {
    "proxy": {
      "/api": {
        "target": "http://localhost:3001/",
        "pathRewrite": {
          "^/api": ""
        },
        "secure": false
      }
    }
  },
  "transpileDependencies": [
    "vuetify"
  ]
}