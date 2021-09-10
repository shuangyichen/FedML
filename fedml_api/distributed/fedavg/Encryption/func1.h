/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */







/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern GoUintptr genShamirShareString_robust(GoSlice shamirShare, GoInt numPeers, GoUint64 logDegree, GoFloat64 scale, GoFloat64 resiliency);

/* Return type for genShamirShares */
struct genShamirShares_return {
	GoUintptr r0; /* SSPoniter */
	GoUintptr r1; /* collectiveKeyShairPointer */
};
extern struct genShamirShares_return genShamirShares(GoInt numPeers, GoUint64 logDegree, GoFloat64 scale, GoFloat64 resiliency);

/* Return type for genCollectiveKeyShare_not_robust */
struct genCollectiveKeyShare_not_robust_return {
	GoUintptr r0; /* PK_pointer */
	GoUintptr r1; /* SS */
};

//func genCollectiveKeyShare_not_robust(numPeers int, logDegree uint64, scale float64, resiliency float64)(PK_pointer uintptr, SS uintptr, res *C.char, shamirShareString *C.char){
extern struct genCollectiveKeyShare_not_robust_return genCollectiveKeyShare_not_robust(GoInt numPeers, GoUint64 logDegree, GoFloat64 scale, GoFloat64 resiliency);

/* Return type for encryptMsg */
struct encryptMsg_return {
	GoUintptr r0; /* encInputList */
	GoInt r1; /* numPieces */
};
extern struct encryptMsg_return encryptMsg(GoSlice inputs, GoSlice cpk, GoSlice shamirShare, GoUint8 robust, GoUint64 logDegree, GoFloat64 scale, GoInt numPeers);
extern GoUintptr genPCKSShare(GoSlice enc_aggr_model, GoSlice TPK, GoSlice shamirShareString, GoInt numPeers, GoUint64 decryptionCoefficient, GoInt inputLength, GoUint8 robust, GoUint64 logDegree, GoFloat64 scale);
extern GoUintptr genCollectivePK(GoSlice cpk, GoInt numPeers, GoUint64 logDegree, GoFloat64 scale);
extern char* genDecryptionCoefficients(GoString clientsParticipated);

/* Return type for aggregateEncrypted */
struct aggregateEncrypted_return {
	GoUintptr r0; /* encResultList */
	GoInt r1; /* numPieces */
};
extern struct aggregateEncrypted_return aggregateEncrypted(GoSlice encInputList, GoInt numPeers, GoUint64 logDegree, GoFloat64 scale, GoInt inputLength);

/* Return type for genTPK */
struct genTPK_return {
	GoUintptr r0; /* tpkPointer */
	GoUintptr r1; /* tskPointer */
};
extern struct genTPK_return genTPK(GoUint64 logDegree, GoFloat64 scale);
extern GoUintptr decrypt(GoString client_chosen, GoSlice tskList, GoSlice pcksShareList, GoSlice encResultList, GoUint64 logDegree, GoFloat64 scale, GoInt inputLength, GoInt numPeers);

#ifdef __cplusplus
}
#endif
