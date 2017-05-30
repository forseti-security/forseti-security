
"""Compilation of serialized models for testing purposes."""

RESOURCE_EXPANSION_1 = {
        'resources':{
                'r/res1' : {
                        'r/res2' : {},
                        'r/res3' : {},
                        'r/res4' : {},
                        'r/res5' : {
                                'r/res6' : {
                                        'r/res7' : {},
                                        'r/res8' : {},
                                    },
                            },
                    },
            },
        'memberships':{},
        'roles':{},
        'bindings':{},
    }

RESOURCE_EXPANSION_2 = {
        'resources':{
                'r/res1' : {
                        'r/res2' : {
                                'r/res3' : {
                                        'r/res4' : {
                                                'r/res5' : {},
                                            },
                                    },
                                'r/res6' : {
                                        'r/res7' : {
                                                'r/res8' : {},
                                            },
                                    },
                            },
                    },
            },
        'memberships':{},
        'roles':{},
        'bindings':{},
    }

MEMBER_TESTING_1 = {
        'resources':{},
        'memberships': {
            'group/g1' : {
                    'group/g1g1' : {
                            'user/g1g1u1' : {}
                        },
                },
            'group/g2' : {
                    'user/g2u1' : {},
                    'user/g2u2' : {},
                    'user/g2u3' : {},
                },
            'group/g3' : {
                    'user/g3u1' : {},
                    'user/g3u2' : {},
                    'user/g3u3' : {},
                    'group/g3g1' : {
                            'user/g3g1u1' : {},
                            'user/g3g1u2' : {},
                            'user/g3g1u3' : {},
                        },
                },
            },
        'roles':{},
        'bindings':{},
    }

RESOURCE_PATH_TESTING_1 = {
        'resources':{
                'r/r1' : {
                        'r/r1r1' : {},
                        'r/r1r2' : {},
                        'r/r1r3' : {
                                'r/r1r3r1' : {
                                        'r/r1r3r1r1' : {},
                                    }
                            },
                        'r/r1r4' : {},
                        'r/r1r5' : {
                                'r/r1r6r1' : {
                                        'r/r1r6r1r1' : {
                                                'r/r1r6r1r1r1' : {},
                                            },
                                    }, 
                            },
                    },
                'r/r2' : {},
                'r/r3' : {},
                'r/r4' : {},
                'r/r5' : {},
            },
        'memberships': {},
        'roles':{},
        'bindings':{},
    }

ROLES_PERMISSIONS_TESTING_1 = {
        'resources':{},
        'memberships':{},
        'roles':{
                'a' : ['a', 'b', 'c', 'd', 'e', 'f'],
                'b' : ['a', 'b', 'c', 'd', 'e'],
                'c' : ['a', 'b', 'c', 'd'],
                'd' : ['a', 'b', 'c'],
                'e' : ['a', 'b'],
                'f' : ['a'],
                'g' : ['a', 'c', 'e'],
                'h' : ['b', 'd', 'f'],
            },
        'bindings':{},
    }

DENORMALIZATION_TESTING_1 = {
        'resources':{
                'r/res1' : {
                        'r/res2' : {
                                'r/res3' : {},
                            },
                    },
            },
        'memberships':{
                'user/u1' : {},
                'user/u2' : {},
                'group/g1' : {},
                'group/g2' : {
                        'user/g2u1' : {},
                        'group/g2g1' : {
                                'user/g2g1u1' : {},
                            },
                    },
            },
        'roles':{
                'a':['a'],
                'b':['b'],
            },
        'bindings':{
            'r/res3' : {
                    'a' : ['user/u1', 'group/g2'],
                },
            'r/res2' : {
                    'a' : ['user/u2'],
                    'b' : ['user/u2', 'user/u1'],
                },
            'r/res1' : {
                    'a' : ['group/g1', 'user/u1'],
                },
            },
    }

ROLES_PREFIX_TESTING_1 = {
        'resources':{},
        'memberships':{},
        'roles':{
                'cloud.admin' : ['cloud.admin'],
                'cloud.reader': ['cloud.reader'],
                'cloud.writer': ['cloud.writer'],
                'db.viewer' : ['db.viewer'],
                'db.writer' : ['db.writer'],
            },
        'bindings':{},
    }

MEMBER_TESTING_2 = {
        'resources':{},
        'memberships':{
                'group/g1' : {
                    },
                'group/g2' : {
                        'group/g3g2g1' : {},
                    },
                'group/g3' : {
                        'group/g3g2' : {
                                'group/g3g2g1' : {
                                    },
                            },
                    },
                'user/u1' : {
                    },
                'user/u2' : {
                    },
            },
        'roles':{},
        'bindings':{},
    }

MEMBER_TESTING_3 = {
        'resources':{},
        'memberships':{
                'group/g1' : {
                        'group/g1g1' : {
                                'user/g1g1u1' : {},
                                'user/g1g1u2' : {},
                                'user/g1g1u3' : {},
                            },
                    },
            },
        'roles':{},
        'bindings':{},
    }

EXPLAIN_GRANTED_1 = {
        'resources':{
            'r/res1' : {
                'r/res2' : {
                    },
                'r/res3' : {
                        'r/res4' : {},
                    },
                },
            },
        'memberships':{
                'user/u1' : {},
                'user/u2' : {},
                'group/g1' : {
                        'user/u3' : {},
                    },
                'group/g2' : {
                        'user/u3' : {},
                    },
                'group/g3' : {
                        'group/g3g1' : {
                                'user/u3' : {},
                                'user/u4' : {},
                            },
                    },
            },
        'roles':{
            'viewer' : ['read','list'],
            'writer' : ['read','list','write'],
            'admin'  : ['read','list','write','delete'],
            },
        'bindings':{
            'r/res1' : {
                    'viewer' : ['group/g1'],
                    'admin'  : ['user/u1'],
                },
            'r/res2' : {
                    'viewer' : ['group/g1'],
                },
            'r/res3' : {
                    'viewer' : ['group/g1'],
                    'writer' : ['group/g3'],
                },
            'r/res4' : {
                    'admin' : ['group/g2'],
                },
            },
    }
