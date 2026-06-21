namespace treehammock.RiggingSupport.Enum;

public enum FeatureSet
{
    basic = 1,
    premium = 2, //Features and unlocked retention limits
    kong = 3, //Premium feature set + XMPP internal application encrypted with commercial pinned (via android and iOS platforms) SSL certs. Individual SSL certs per platform.
    rawrzilla = 4, //Premium feature set + Increased security via raised two factor auth limits and a few additional two factor auth combination patterns
    bigbrain = 5, //Premium feature set + kong feature set + rawzilla feature set
    offsite = 6,
    solokong = 7, //XMPP internal application encrypted with commercial pinned (via android and iOS platforms) SSL certs. Individual SSL certs per platform.
    solorawrzilla = 8, //Increased security via raised two factor auth limits and a few additional two factor auth combination patterns
}
