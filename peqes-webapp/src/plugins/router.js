import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);

import ResearcherView from '../views/ResearcherView';
import EthicsBoardView from '../views/EthicsBoardView';
import ParticipantView from '../views/ParticipantView';

const router = new VueRouter({
    routes: [{
        name: 'researcher',
        path: '/researcher',
        component: ResearcherView
    }, {
        name: 'ethicsboard',
        path: '/ethicsboard',
        component: EthicsBoardView
    }, {
        name: 'participant',
        path: '/participant',
        component: ParticipantView
    }, {
        path: '/',
        redirect: '/researcher'
    }]
});

export default router;
