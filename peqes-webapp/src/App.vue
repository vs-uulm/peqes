<template>
  <v-app>
    <v-app-bar app :color="roles[$router.currentRoute.name].color" dark>
      <div class="d-flex align-center">
        <v-img alt="Logo" class="shrink mr-2" contain src="@/assets/icon.png" transition="scale-transition" width="40" />
        <v-toolbar-title>PeQES ({{ roles[$router.currentRoute.name].title }})</v-toolbar-title>
      </div>

      <v-spacer></v-spacer>

      <v-btn class="ma-2 d-none d-sm-flex" href="https://github.com/vs-uulm/peqes">
          <v-icon left>mdi-github</v-icon>
          View on GitHub
      </v-btn>

      <v-btn text icon class="d-flex d-sm-none" href="https://github.com/vs-uulm/peqes">
          <v-icon>mdi-github</v-icon>
      </v-btn>

      <v-menu offset-y>
        <template v-slot:activator="{ on }">
          <v-btn v-on="on" class="d-none d-sm-flex">
            <v-icon left>mdi-account-box-multiple-outline</v-icon>
            Select Role
            <v-icon right>mdi-menu-down</v-icon>
          </v-btn>

          <v-btn v-on="on" text icon class="d-flex d-sm-none">
              <v-icon>mdi-menu</v-icon>
          </v-btn>
        </template>
        <v-list>
          <v-list-item v-for="(role, key) in roles" :key="key" :to="key">
            <v-list-item-icon><v-icon v-text="role.icon"></v-icon></v-list-item-icon>
            <v-list-item-title>{{ role.title }}</v-list-item-title>
          </v-list-item>
        </v-list>
      </v-menu>
    </v-app-bar>

    <v-content class="mt-5">
      <v-layout wrap>
        <v-flex>
          <v-container>
            <h1 class="display-2 font-weight-bold mb-3">
                {{ roles[$router.currentRoute.name].title }} View
            </h1>

            <router-view />
          </v-container>
        </v-flex>
      </v-layout>
    </v-content>
  </v-app>
</template>

<script>
export default {
  name: 'App',

  data: () => ({
    roles: {
      researcher: {
        title: 'Researcher',
        icon: 'mdi-school',
        color: '#56AA1C'
      },

      ethicsboard: {
        title: 'Ethics Board',
        icon: 'mdi-account-group',
        color: '#A32638'
      },

      participant: {
        title: 'Participant',
        icon: 'mdi-account',
        color: '#BD6005'
      }
    }
  })
};
</script>
