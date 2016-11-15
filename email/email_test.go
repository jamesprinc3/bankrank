package email

import (
    //"fmt"
    //"net"
    "testing"
    "reflect"
    // "time"
    //reflections "github.com/oleiade/reflections"
)

var ParseDKIMSigTests = []struct {
    record string

    result DKIMSigProfile
}{
    {record: `v=1`,
     result: DKIMSigProfile{V:1,},
     },
    {record: `v=1; a=rsa-sha256; d=example.net; s=brisbane;
     c=relaxed/simple; q=dns/txt; l=1234; t=1117574938; x=1118006938;
     h=from:to:subject:date:keywords:keywords;
     bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
     b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR;
     z=From:foo@eng.example.net|To:joe@example.com|Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700`,
     result: DKIMSigProfile{V:1, A:"rsa-sha256", D:"example.net", S:"brisbane",
                          C:"relaxed/simple", Q:"dns/txt", L:1234, T:1117574938,
                          X:1118006938, H:[]string{"from", "to", "subject", "date", "keywords", "keywords"},
                          BH:"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                          B:"dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR",
                          Z:map[string]string{"From":"foo@eng.example.net", "To":"joe@example.com",
                                              "Subject":"demo=20run", "Date":"July=205,=202005=203:44:08=20PM=20-0700"}},
     },
    {record: `v=1; a=rsa-sha256; c=simple/simple;  d=information.natwest.com;
             i=@information.natwest.com;  q=dns/txt; s=mail; t=1462844746; x=1494380746;
             h=message-id:date:from:to:subject:mime-version:   content-transfer-encoding;
             bh=Vq/vP4CFQA5eYLaSAGG07LEMQiHvUQ53z2M5UvFlf3Q=;
             b=ooEK+zWITEXLRmoX6PX5sajrb4EkE4/tPYI5Afyeh6xrBfPshsCBCQ5T
             lkbZgrgq52gcM6SJq16IivSb2AA2IWY1Dr64xeP/MerZOpr2ZVrQh+fKN
             p9u3920oZtXbRlXtjIf8b5ZE3pwSFjZjzs/s+77EEUJR9L0jk7oigk0mG   0=`,
     result: DKIMSigProfile{V:1, A:"rsa-sha256", D:"information.natwest.com", C:"simple/simple", 
                          I:"@information.natwest.com", Q:"dns/txt", S:"mail", T:1462844746,
                          X:1494380746, H:[]string{"message-id", "date", "from", "to", "subject", "mime-version", "content-transfer-encoding"},
                          BH:"Vq/vP4CFQA5eYLaSAGG07LEMQiHvUQ53z2M5UvFlf3Q=",
                          B:`ooEK+zWITEXLRmoX6PX5sajrb4EkE4/tPYI5Afyeh6xrBfPshsCBCQ5TlkbZgrgq52gcM6SJq16IivSb2AA2IWY1Dr64xeP/MerZOpr2ZVrQh+fKNp9u3920oZtXbRlXtjIf8b5ZE3pwSFjZjzs/s+77EEUJR9L0jk7oigk0mG0=`},
    },
    {record: `v=1; a=rsa-sha256; c=relaxed/simple; d=facebookmail.com;
    s=s1024-2013-q3; t=1464759990;
    bh=cHolsXpoNuT6L7FN2uG8o/dS+u+JNIhOsDOE4UUSF3w=;
    h=Date:To:Subject:From:MIME-Version:Content-Type;
    b=S2JGWZRKFo/K8vuNSTvYxKbjza+AsnhabkgEki+3adpGzCNODBJP+pFpUoZeS+xbq
 8W/3xZful8j5jybv4Xlrv1z4ssyK7ZAsVHRbpIFHH6RjefE7z/+Qs4idagVv83WE4L
 ZvTFIVADIwin1BA+cLLXlgEePjHZ0sf9KdAhLjTM=`,
    result: DKIMSigProfile{V:1, A:"rsa-sha256", C:"relaxed/simple", D:"facebookmail.com",
                           S:"s1024-2013-q3", T:1464759990, BH:"cHolsXpoNuT6L7FN2uG8o/dS+u+JNIhOsDOE4UUSF3w=",
                           H:[]string{"Date", "To", "Subject", "From", "MIME-Version", "Content-Type"},
                           B: `S2JGWZRKFo/K8vuNSTvYxKbjza+AsnhabkgEki+3adpGzCNODBJP+pFpUoZeS+xbq8W/3xZful8j5jybv4Xlrv1z4ssyK7ZAsVHRbpIFHH6RjefE7z/+Qs4idagVv83WE4LZvTFIVADIwin1BA+cLLXlgEePjHZ0sf9KdAhLjTM=`}},
}


func TestParseDKIMSig(t *testing.T) {
    for _, tt := range ParseDKIMSigTests {  

        if p := ParseDKIMSig(tt.record); !reflect.DeepEqual(&tt.result, p) {
            t.Errorf("ParseDKIMSig was %q \n want %q\n", p, tt.result)
        }
    }
}