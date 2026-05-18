# Meta Ads Upload Skill

## Naming Convention
Ads follow this pattern: {number} Ad {variant} {market}
Examples: 7 Ad 1 ES, 7 Ad 2A ES, 7 Ad 2B ES, 7 Ad 3 ES

## Image Matching
- Post image: filename contains "Post" → use for Feed + Search
- Story image: filename contains "Story" → use for Stories + Reels
- Always pair Post and Story from same ad number

## Placement Rules
- Post images: Feed, Search results ONLY
- Story images: Stories, Reels ONLY
- Never mix placements

## Campaign Defaults
- Objective: OUTCOME_SALES
- Status: ACTIVE unless told otherwise
- Bid strategy: LOWEST_COST_WITHOUT_CAP
- Advantage audience: disabled (0)
- Translation: Translate selected creatives only

## Copy Matching
- Ad 1 = Health/Better Choice angle
- Ad 2A = Gym Fat Loss angle
- Ad 2B = Gym Muscle Gain angle
- Ad 3 = Taste/Flavor angle
- Ad 4 = Bundle/Price angle

## Upload Process
1. Read copy document fully before starting
2. Match Post/Story pairs by filename
3. Upload all images first to get hashes
4. Create all ad creatives
5. Create ads in batch
6. Report all created IDs
